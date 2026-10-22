"""Wave 4.3-b Lane f-b1-insights (T8: Human insights closed loop) acceptance tests.

Covers the §9 T8 acceptance criteria:
1. Redaction of secrets, PII, paths, IPs, and high-entropy tokens + 300-char cap + benign identifier preservation.
2. Correction-cue detection precision/recall and user-scope hook storage (heartbeat vs cue-gated insight).
3. 'Agent insights don't count': MCP aegis_capture_insight suggestions never count and never enter aegis_scan; a hook prompt of the same host within the join window that contains the quote annotates, never upgrades.
4. Keyed hs pseudonymization (HMAC-SHA256 with ~/.aegis/link.key, POSIX mode 0600, O_EXCL, 32 random bytes).
5. Stdlib TF-IDF top-3 neighbour clustering, exposure-joined rule matching, and rejected-cluster cooldown (>= 2 new insights).
6. Closed-template proposals in .aegis/proposals/<id>.md (never loaded by load_rules, no verbatim W0/W2 text) and post-activation recurrence measurement over heartbeat-alive sessions (burst collapse, 95% UCB, >= 3 alarm, per-rev reset).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Dict

import pytest

from aegis_core import gitsafe
from aegis_core.insights import (
     KEY_SIZE,
    add_insight,
    capture_suggestion,
    create_link_key,
    has_correction_cue,
    insights_path,
    measure_recurrence,
    read_insight_rows,
    read_link_key,
    record_decision,
    record_hook_prompt,
    redact_insight_text,
    review_insights,
    session_hs,
    write_proposal,
)
from aegis_core.rules import load_rules
from aegis_core.scan import scan as scan_workspace
from aegis_core.storage import append_jsonl
from aegis_core.telemetry_engine import ledger


def _init_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test User"], check=True)
    rules_dir = path / ".aegis" / "rules" / "traps"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (path / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (path / "src").mkdir(exist_ok=True)
    (path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "init"], check=True)
    return path


def _write_rule(repo: Path, rule_id: str, target_paths: list[str], body: str, *, archived: bool = False) -> Path:
    base = repo / ".aegis" / "rules"
    folder = (base / ".archive" / "traps") if archived else (base / "traps")
    folder.mkdir(parents=True, exist_ok=True)
    targets = "\n".join(f"  - {p}" for p in target_paths)
    content = (
        f"---\n"
        f"id: {rule_id}\n"
        f"type: trap\n"
        f"enforcement: advisory\n"
        f"hypothesis: Prevent recurring defect in {rule_id}.\n"
        f"target_paths:\n{targets}\n"
        f"---\n"
        f"# {rule_id}\n\n{body}\n"
    )
    target = folder / f"{rule_id}.md"
    target.write_text(content, encoding="utf-8")
    return target


def _hook_insight(repo: Path, text: str, session: str, home: Path) -> Dict[str, Any]:
    """A keyed-hs insight as the host delivers it: a hook payload, never a typed argument.
    The hook takes its paths from the dirty set, so src/app.py is made dirty first, as the
    explicit ``paths=["src/app.py"]`` of the CLI channel did."""
    (repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
    row = record_hook_prompt(repo, "claude-code", {"prompt": text, "session_id": session, "cwd": str(repo)}, home=home)
    assert row.get("event") == "insight", f"no correction cue in {text!r}"
    return row


# ── 1. Redaction & 300-char cap ──────────────────────────────────────────────

def test_redaction_strips_secrets_and_caps_at_300_chars_while_preserving_identifiers():
    pem = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----"
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    aws = "".join(["AKIA", "IOSFODNN7EXAMPLE"])
    gh_pat = "".join(["ghp_", "1234567890abcdefghijklmnopqrstuvwxyzABCD"])
    gl_pat = "".join(["glpat-", "1234567890abcdefghij"])
    openai_key = "".join(["sk-proj-", "1234567890abcdefghijklmnop"])
    stripe_key = "".join(["sk_live_", "1234567890abcdefghijklmn"])
    slack_tok = "".join(["xoxb-", "123456789012-1234567890123-abcdef"])
    google_key = "".join(["AIza", "SyDaGmWKa4JsXZ-HjGw7x8_1234567890abc"])
    url_cred = "https://admin:myS3cretP@ss@db.internal.example.com:5432/prod"
    bearer = "Bearer " + "ey9876543210abcdefghijklmnop"
    kv_secret = 'api_key="top_secret_value_98765"'
    email = "jane.doe+dev@corp.example.org"
    home_linux = "/home/nseney/Documents/citadel/aegis_core/storage.py"
    home_mac = "/Users/alexsmith/projects/aegis/cli.py"
    ip_addr = "192.168.42.109"
    hi_ent = "x9Kp2mQ8vL4nR7wZ1jF5bT3yH6c"

    raw = (
        f"Stop leaking {pem} or {jwt} or {aws} or {gh_pat} or {gl_pat} or {openai_key} "
        f"or {stripe_key} or {slack_tok} or {google_key} or {url_cred} or {bearer} "
        f"or {kv_secret} or {email} or {home_linux} or {home_mac} or {ip_addr} or {hi_ent}"
    )
    # Test full redaction with a generous limit first to verify every pattern
    redacted_full = redact_insight_text(raw, max_len=2000)
    for secret in (
        "MIIEpAIBAAKCAQEA1234567890abcdef",
        jwt,
        aws,
        gh_pat,
        gl_pat,
        openai_key,
        stripe_key,
        slack_tok,
        google_key,
        "myS3cretP",
        "ey9876543210abcdefghijklmnop",
        "top_secret_value_98765",
        email,
        "/home/nseney",
        "/Users/alexsmith",
        ip_addr,
        hi_ent,
    ):
        assert secret not in redacted_full, f"secret leaked: {secret}"

    # Verify default <= 300 char cap after redaction
    capped = redact_insight_text(raw)
    assert len(capped) <= 300

    # Verify benign identifiers, paths, sha256, and UUIDs survive untouched
    benign = (
        "Do not call snake_case_identifier_name or CamelCaseIdentifierName in "
        "aegis_core/telemetry_engine/ledger.py for commit "
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4 or id 550e8400-e29b-41d4-a716-446655440000"
    )
    redacted_benign = redact_insight_text(benign)
    assert "snake_case_identifier_name" in redacted_benign
    assert "CamelCaseIdentifierName" in redacted_benign
    assert "aegis_core/telemetry_engine/ledger.py" in redacted_benign
    assert "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4" in redacted_benign
    assert "550e8400-e29b-41d4-a716-446655440000" in redacted_benign


# ── 2. Correction cues & hook storage ────────────────────────────────────────

def test_correction_cue_detector_precision_and_recall_and_hook_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")
    # Dirty a file so git dirty set is non-empty
    (repo / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")

    positives = [
        "No, don't mock the filesystem in integration tests.",
        "I already told you to use atomic_write_bytes.",
        "That is wrong and breaks the storage ratchet.",
        "Use gitsafe.run instead of subprocess.Popen.",
        "Why did you modify a file outside our lane?",
        "Revert that change to cli.py immediately.",
        "Stop adding extra keys to MCP annotations.",
    ]
    for text in positives:
        assert has_correction_cue(text) is True, f"missed positive cue: {text}"

    negatives = [
        "Please implement the parser for the new command.",
        "Run pytest on the unit test directory.",
        "Can you explain how the ledger index works?",
        "Create a helper function for formatting timestamps.",
        "Let us check the current branch status.",
    ]
    for text in negatives:
        assert has_correction_cue(text) is False, f"false positive cue: {text}"

    # Routine prompt via hook -> writes heartbeat only, no prompt text on disk
    record_hook_prompt(
        repo,
        "claude-code",
        {"prompt": "Please implement the parser for the new command.", "session_id": "sess-routine-1", "cwd": str(repo)},
        home=home,
    )
    store = insights_path(repo, home=home)
    assert store.exists()
    assert not store.is_relative_to(repo)
    if os.name == "posix":
        assert stat.S_IMODE(store.stat().st_mode) == 0o600

    rows = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["event"] == "heartbeat"
    assert "text" not in rows[0]
    assert "Please implement" not in store.read_text(encoding="utf-8")

    # Correction prompt via hook -> writes heartbeat (for new session) + redacted W2 insight row
    record_hook_prompt(
        repo,
        "claude-code",
        {
            "prompt": "No, don't hardcode token ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD in src/app.py!",
            "session_id": "sess-corr-2",
            "cwd": str(repo),
        },
        home=home,
    )
    rows = [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines() if line.strip()]
    insight_rows = [r for r in rows if r.get("event") == "insight"]
    assert len(insight_rows) == 1
    ins = insight_rows[0]
    assert ins["level"] in ("W2", "hook")
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD" not in ins["text"]
    assert len(ins["text"]) <= 300
    assert "src/app.py" in ins["paths"]
    assert ins["psrc"] == "dirty"


# ── 3. Agent insights don't count ────────────────────────────────────────────

def test_agent_suggestions_do_not_count_and_never_enter_scan_or_proposals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")
    _write_rule(repo, "trap-existing", ["src/*.py"], "Never use eval on untrusted input.")

    # Agent captures 3 unconfirmed suggestions via capture_suggestion / MCP
    for i in range(3):
        res = capture_suggestion(
            repo,
            quote="Never use write_text with newline parameter in Python 3.9",
            paths=["src/app.py"],
            host="claude-code",
            session=f"unconfirmed-sess-{i}",
            home=home,
        )
        assert res["level"] == "suggestion"

    review = review_insights(repo, home=home)
    # Suggestions appear only in review['suggestions'], never in countable clusters/proposals
    assert len(review["suggestions"]) == 3
    assert review["clusters"] == []

    # aegis_scan never returns suggestion text
    scan_res = scan_workspace(repo, changed_files=["src/app.py"])
    scan_dump = json.dumps(scan_res)
    assert "newline parameter" not in scan_dump

    # A hook-captured prompt of the same host containing the quote corroborates the captures:
    # they stay suggestions and annotate the one hook row, which alone counts.
    hook = record_hook_prompt(
        repo,
        "claude-code",
        {
            "prompt": "Stop! Never use write_text with newline parameter in Python 3.9, it breaks!",
            "session_id": "host-sess-1",
            "cwd": str(repo),
        },
        home=home,
    )
    corroborated = capture_suggestion(
        repo,
        quote="Never use write_text with newline parameter in Python 3.9",
        paths=["src/app.py"],
        host="claude-code",
        session="server-uuid-1",
        home=home,
    )
    assert corroborated["level"] == "suggestion"
    assert corroborated["corroborated_by"] == hook["id"]
    review = review_insights(repo, home=home)
    assert [(c["count"], len(c["corroborated"])) for c in review["clusters"]] == [(1, 4)]
    assert review["suggestions"] == []


# ── 4. Keyed hs pseudonymization & link.key ──────────────────────────────────

def test_keyed_hs_pseudonymization_and_link_key_creation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")

    key_path, created = create_link_key(home)
    assert created is True
    assert key_path == home / ".aegis" / "link.key"
    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    raw_key = read_link_key(home)
    assert raw_key is not None and len(raw_key) == KEY_SIZE == 32

    # Idempotent O_EXCL: second call does not overwrite key
    _, created_again = create_link_key(home)
    assert created_again is False
    assert read_link_key(home) == raw_key

    native_session = "raw-secret-session-uuid-9999"
    expected_hs = hmac.new(
        raw_key,
        b"aegis-hs/v1\x00claude-code\x00" + native_session.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()[:32]
    assert session_hs("claude-code", native_session, raw_key) == expected_hs

    _hook_insight(repo, "Don't use bare except blocks in storage handlers.", native_session, home)
    raw_file = insights_path(repo, home=home).read_text(encoding="utf-8")
    assert native_session not in raw_file
    row = json.loads(raw_file.splitlines()[-1])
    assert row["hs"] == expected_hs
    assert "session" not in row and "host_session" not in row


# ── 5. TF-IDF clustering, rule matching, and rejected cooldown ───────────────

def test_tfidf_clustering_rule_matching_and_rejected_cluster_cooldown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")

    # Active rule 1: exposed in session-exposed-1
    r1_path = _write_rule(
        repo,
        "trap-no-shell-true",
        ["src/*.py"],
        "Never pass shell=True to subprocess calls in src modules.",
    )
    r1_rule = load_rules(repo).get("trap-no-shell-true")
    assert r1_rule is not None
    r1_rev = r1_rule.digest

    # Active rule 2: NOT exposed in any session
    _write_rule(
        repo,
        "trap-no-eval",
        ["src/*.py"],
        "Never call eval or exec on dynamic strings in src modules.",
    )

    # Archived rule
    _write_rule(
        repo,
        "trap-archived-pickle",
        ["src/*.py"],
        "Do not deserialize pickle payloads from untrusted sockets.",
        archived=True,
    )

    # A persisted exposure of trap-no-shell-true at its rev, on the same host as the hook (the
    # MCP server's session id never equals the host's, so the join is host + window + rev).
    from aegis_core import credit

    credit.record_exposure(repo, "claude-code", "mcp-server-uuid", ["trap-no-shell-true"],
                           revs={"trap-no-shell-true": r1_rev[:16]})

    # Add insight matching the exposed rule on the same host within the window -> exposed_and_ignored
    _hook_insight(repo, "Do not pass shell=True to subprocess calls in src/app.py", "session-exposed-1", home)

    # Add insight matching trap-no-eval in session without exposure -> not_exposed
    _hook_insight(repo, "Never call eval or exec on dynamic strings in src/app.py", "session-unexposed-2", home)

    # Add insight matching archived rule -> matches_archived
    _hook_insight(repo, "Do not deserialize pickle payloads from untrusted sockets in src/app.py", "session-unexposed-3", home)

    # Add two similar insights with no matching rule -> cluster together with no_rule
    ins_a = _hook_insight(repo, "Stop mutating global os.environ directly inside worker threads", "session-4", home)
    ins_b = _hook_insight(repo, "Never mutate global os.environ state inside worker threads", "session-5", home)

    rev = review_insights(repo, home=home)
    classifications = {c["match_status"]: c for c in rev["clusters"]}
    assert "exposed_and_ignored" in classifications
    assert classifications["exposed_and_ignored"]["matched_rule"] == "trap-no-shell-true"
    assert "not_exposed" in classifications
    assert classifications["not_exposed"]["matched_rule"] == "trap-no-eval"
    assert "matches_archived" in classifications
    assert classifications["matches_archived"]["matched_rule"] == "trap-archived-pickle"
    assert "no_rule" in classifications
    no_rule_cluster = classifications["no_rule"]
    assert len(no_rule_cluster["insight_ids"]) == 2
    assert set(no_rule_cluster["insight_ids"]) == {ins_a["id"], ins_b["id"]}

    # Reject the no_rule cluster -> disappears from review until >= 2 new insights arrive
    cluster_id = no_rule_cluster["cluster_id"]
    record_decision(
        repo,
        cluster_id=cluster_id,
        decision="reject",
        insight_ids=no_rule_cluster["insight_ids"],
        reason="Not needed right now",
        home=home,
    )
    rev_after_reject = review_insights(repo, home=home)
    assert all(c["cluster_id"] != cluster_id for c in rev_after_reject["clusters"])

    # 1 new insight arrives -> still suppressed (< 2 new insights since rejection)
    _hook_insight(repo, "Do not mutate global os.environ variables inside worker threads", "session-6", home)
    rev_after_one = review_insights(repo, home=home)
    assert not any("os.environ" in " ".join(c.get("excerpts", [])) for c in rev_after_one["clusters"])

    # 2nd new insight arrives -> cluster re-surfaces!
    # "Don't", not "Avoid": the hook records only prompts with a correction cue.
    _hook_insight(repo, "Don't mutate global os.environ dictionary in worker threads", "session-7", home)
    rev_after_two = review_insights(repo, home=home)
    resurfaced = [c for c in rev_after_two["clusters"] if c["match_status"] == "no_rule"]
    assert len(resurfaced) == 1
    assert len(resurfaced[0]["insight_ids"]) >= 2


# ── 6. Closed-template proposals & recurrence measurement ────────────────────

def test_closed_template_proposals_and_recurrence_alarm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")

    # Capture a W2 hook insight with distinctive verbatim phrasing
    verbatim_w2 = "No, never call shutil.rmtree on unvalidated user paths in src/app.py!"
    record_hook_prompt(
        repo,
        "claude-code",
        {"prompt": verbatim_w2, "session_id": "sess-prop-1", "cwd": str(repo)},
        home=home,
    )

    # Write closed-template proposal -> lives in .aegis/proposals/<id>.md, never loaded by load_rules,
    # and never contains verbatim W0/W2 text.
    member = add_insight(repo, "Recursive deletes need a confinement check first", paths=["src/app.py"],
                         kind="filesystem_safety", home=home)
    prop_path = write_proposal(
        repo,
        proposal_id="trap-validate-rmtree",
        summary_bullets=["Validate path confinement before recursive directory deletion."],
        insight_ids=[member["id"]],
        home=home,
    )
    assert prop_path == repo / ".aegis" / "proposals" / "trap-validate-rmtree.md"
    assert prop_path.exists()
    prop_text = prop_path.read_text(encoding="utf-8")
    assert verbatim_w2 not in prop_text
    assert load_rules(repo).get("trap-validate-rmtree") is None

    # Attempting to pass verbatim W2 text into write_proposal is rejected or sanitized
    with pytest.raises(ValueError):
        write_proposal(
            repo,
            proposal_id="trap-bad-verbatim",
            summary_bullets=[verbatim_w2],
            insight_ids=[member["id"]],
            home=home,
        )

    # Activate rule in .aegis/rules/traps/ and test recurrence measurement
    rule_file = _write_rule(
        repo,
        "trap-validate-rmtree",
        ["src/*.py"],
        "Always check path confinement before recursive directory removal.",
    )

    # Initially 0 heartbeat sessions after rule activation -> status == "no_prompt_traffic"
    rec0 = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert rec0["status"] == "no_prompt_traffic"
    assert rec0["sessions"] == 0
    assert rec0["alarm"] is False

    # Simulate 5 heartbeat-alive sessions, 3 of which have recurrence insights (with a burst in session 1)
    for s_idx in range(1, 6):
        sid = f"post-act-sess-{s_idx}"
        record_hook_prompt(
            repo,
            "claude-code",
            {"prompt": "Run the test suite please.", "session_id": sid, "cwd": str(repo)},
            home=home,
        )
        if s_idx <= 3:
            # In session 1, emit two burst insights back-to-back -> must collapse to 1 episode
            repeats = 2 if s_idx == 1 else 1
            for _ in range(repeats):
                _hook_insight(
                    repo, "Stop calling recursive directory removal without path confinement check in src/app.py", sid, home)

    rec1 = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert rec1["sessions"] == 5
    assert rec1["recurrences"] == 3
    assert rec1["alarm"] is True
    assert rec1["status"] == "not_working"
    assert 0.0 < rec1["rate_ucb95"] <= 1.0

    # Updating the rule content (new rev) resets post-activation recurrence count
    rule_file.write_text(
        rule_file.read_text(encoding="utf-8") + "\nAdditional mechanical guidance for v2.\n",
        encoding="utf-8",
    )
    rec_reset = measure_recurrence(repo, "trap-validate-rmtree", home=home, reset_on_rev_change=True)
    assert rec_reset["recurrences"] == 0
    assert rec_reset["alarm"] is False


def test_same_rule_dissimilar_insights_stay_separate_through_rejection_and_resurfacing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")

    _write_rule(
        repo,
        "trap-broad-security",
        ["src/*.py"],
        "Never invoke subprocess with shell=True command execution and never call pickle.loads on untrusted socket payloads.",
    )

    ins_shell = _hook_insight(repo, "Stop invoking subprocess with shell=True command execution", "sess-shell-1", home)
    ins_pickle = _hook_insight(repo, "Never call pickle.loads on untrusted socket payload bytes", "sess-pickle-1", home)

    rev = review_insights(repo, home=home)
    clusters = rev["clusters"]
    assert len(clusters) == 2
    assert {c["matched_rule"] for c in clusters} == {"trap-broad-security"}
    assert len({c["cluster_id"] for c in clusters}) == 2

    cluster_shell = next(c for c in clusters if ins_shell["id"] in c["insight_ids"])
    cluster_pickle = next(c for c in clusters if ins_pickle["id"] in c["insight_ids"])
    assert cluster_shell["cluster_id"] != cluster_pickle["cluster_id"]

    # Reject cluster 1 (shell) -> cluster 1 is suppressed while cluster 2 (pickle) remains active
    record_decision(
        repo,
        cluster_id=cluster_shell["cluster_id"],
        decision="reject",
        insight_ids=cluster_shell["insight_ids"],
        reason="Handled by separate lint check",
        home=home,
    )

    rev_after_reject = review_insights(repo, home=home)
    active_ids_after_reject = [c["cluster_id"] for c in rev_after_reject["clusters"]]
    assert cluster_pickle["cluster_id"] in active_ids_after_reject
    assert cluster_shell["cluster_id"] not in active_ids_after_reject
    assert len(rev_after_reject["clusters"]) == 1
    assert len(rev_after_reject["suppressed_clusters"]) == 1

    # Add 2 more insights similar to cluster 1 -> cluster 1 resurfaces alongside cluster 2
    _hook_insight(repo, "Do not invoke subprocess with shell=True command execution", "sess-shell-2", home)
    _hook_insight(repo, "Don't invoke subprocess with shell=True command execution", "sess-shell-3", home)

    rev_resurfaced = review_insights(repo, home=home)
    assert len(rev_resurfaced["clusters"]) == 2
    resurfaced_shell = next(c for c in rev_resurfaced["clusters"] if ins_shell["id"] in c["insight_ids"])
    resurfaced_pickle = next(c for c in rev_resurfaced["clusters"] if ins_pickle["id"] in c["insight_ids"])
    assert len(resurfaced_shell["insight_ids"]) == 3
    assert len(resurfaced_pickle["insight_ids"]) == 1


def test_recurrence_reports_insufficient_session_identity_when_hs_is_missing_and_never_inflates_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")

    _write_rule(
        repo,
        "trap-validate-rmtree",
        ["src/*.py"],
        "Always check path confinement before recursive directory removal.",
    )

    # Seed 10 legacy heartbeats without session identity (4.3 wrote one per session-less
    # prompt); a session-less prompt writes none now (R-structure-a2).
    rev = load_rules(repo).get("trap-validate-rmtree").digest[:16]
    legacy = {"v": 1, "ts": "2026-10-20T00:00:00Z", "event": "heartbeat", "host": "claude-code",
              "revs": {"trap-validate-rmtree": rev}}
    store = insights_path(repo, home=home)
    store.parent.mkdir(parents=True, exist_ok=True)
    append_jsonl(store, [dict(legacy) for _ in range(10)])
    for _ in range(10):
        record_hook_prompt(
            repo,
            "claude-code",
            {"prompt": "Please run the unit tests.", "cwd": str(repo)},
            home=home,
        )
    assert len(read_insight_rows(repo, home=home)) == 10

    rec_missing = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert rec_missing["status"] == "insufficient_session_identity"
    assert rec_missing["sessions"] == 0
    assert rec_missing["unidentified_heartbeats"] == 10
    assert rec_missing["alarm"] is False

    # Now add 2 identified sessions (hs present) -> sessions must be 2, not 12
    for s_idx in (1, 2):
        record_hook_prompt(
            repo,
            "claude-code",
            {"prompt": "Please run the unit tests.", "session_id": f"identified-sess-{s_idx}", "cwd": str(repo)},
            home=home,
        )

    rec_mixed = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert rec_mixed["sessions"] == 2
    assert rec_mixed["unidentified_heartbeats"] == 10
    assert rec_mixed["status"] == "ok"


def test_insights_file_created_with_0600_mode_before_first_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")
    store = insights_path(repo, home=home)

    real_open = os.open
    real_write = os.write
    open_modes: list[int] = []
    write_modes: list[int] = []
    tracked_fds: set[int] = set()

    def spy_open(path: Any, flags: int, mode: int = 0o777, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, flags, mode, *args, **kwargs)
        if Path(str(path)) == store:
            open_modes.append(stat.S_IMODE(mode))
            tracked_fds.add(fd)
        return fd

    def spy_write(fd: int, data: Any) -> int:
        if fd in tracked_fds and os.name == "posix":
            write_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real_write(fd, data)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "write", spy_write)

    saved_umask = os.umask(0o022) if os.name == "posix" else None
    try:
        add_insight(repo, "Never leave new user insight files world-readable during write.", paths=["src/app.py"], home=home)
    finally:
        if saved_umask is not None:
            os.umask(saved_umask)

    assert open_modes == [0o600]
    if os.name == "posix":
        assert write_modes and all(m == 0o600 for m in write_modes)
        assert stat.S_IMODE(store.stat().st_mode) == 0o600


def test_ordinary_mcp_aegis_scan_records_exposure_for_review_insights_without_outcome_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from aegis_core import credit
    from aegis_mcp.tools import execute_tool

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")

    _write_rule(
        repo,
        "trap-no-shell-true",
        ["src/*.py"],
        "Never pass shell=True to subprocess calls in src modules.",
    )

    scan_res = execute_tool(
        "aegis_scan",
        {
            "workspace": str(repo),
            "files": ["src/app.py"],
            "_host": "claude-code",
            "_session": "session-exposed-1",
        },
    )
    assert scan_res.get("status") != "FAIL"
    assert ledger.read(repo).rows == []

    _hook_insight(repo, "Do not pass shell=True to subprocess calls in src/app.py", "session-exposed-1", home)

    rev_in_mem = review_insights(repo, home=home)
    assert len(rev_in_mem["clusters"]) == 1
    assert rev_in_mem["clusters"][0]["matched_rule"] == "trap-no-shell-true"
    assert rev_in_mem["clusters"][0]["match_status"] == "exposed_and_ignored"

    # Simulate a fresh CLI process where in-memory _EXPOSED is empty: persisted exposure still matches
    credit._EXPOSED.clear()
    rev_persisted = review_insights(repo, home=home)
    assert len(rev_persisted["clusters"]) == 1
    assert rev_persisted["clusters"][0]["matched_rule"] == "trap-no-shell-true"
    assert rev_persisted["clusters"][0]["match_status"] == "exposed_and_ignored"


def test_human_level_h_insight_requires_content_bound_signed_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from aegis_core import human_gate
    from tests import helpers_humangate as hg

    if not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    human_key, human_pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, human_pub)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "changed"))
    repo.commit("edit rule")
    gov_digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    gov_commit = repo.commit(
        f"chore: approve governance\n\nAegis-Approve: {gov_digest}\n",
        sign_key=human_key,
        allow_empty=True,
    )

    text_a = "Validate symlink confinement before opening user state files."
    text_b = "Avoid mutable default arguments in public SDK helpers."

    assert add_insight(repo.root, text_a, commit=None, base_ref="main", home=home)["level"] == "cli"
    assert add_insight(repo.root, text_a, commit=gov_commit, base_ref="main", home=home)["level"] == "cli"

    insight_commit = repo.commit(
        f"chore: approve insight\n\n{human_gate.INSIGHT_APPROVE_TRAILER}: {human_gate.insight_text_hash(text_a)}\n",
        sign_key=human_key,
        allow_empty=True,
    )
    assert add_insight(repo.root, text_a, commit=insight_commit, base_ref="main", home=home)["level"] == "H"
    assert add_insight(repo.root, text_b, commit=insight_commit, base_ref="main", home=home)["level"] == "cli"
    assert add_insight(repo.root, text_a, commit=None, base_ref="main", home=home)["level"] == "cli"



def test_a_4_3_upgraded_w2_capture_never_counts_as_a_recurrence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _init_git_repo(tmp_path / "repo")
    _write_rule(repo, "trap-validate-rmtree", ["src/*.py"], "Always check path confinement before recursive directory removal.")
    hb = record_hook_prompt(repo, "claude-code", {"prompt": "Please run the tests.", "session_id": "s1", "cwd": str(repo)},
                            home=home)
    rev = load_rules(repo).get("trap-validate-rmtree").digest[:16]
    append_jsonl(insights_path(repo, home=home), [{
        "v": 1, "ts": hb["ts"], "event": "insight", "id": "ins-0000000000cc", "level": "W2",
        "text": "stop calling recursive directory removal without path confinement check", "paths": ["src/app.py"],
        "psrc": "explicit", "host": "claude-code", "hs": hb["hs"], "confirmed_by": "ins-000000000001",
        "revs": {"trap-validate-rmtree": rev}}])
    rec = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert (rec["sessions"], rec["recurrences"]) == (1, 0)


# ── R-evidence-38: review decisions take effect ─────────────────────────────────

ENV_TEXTS = (
    "Stop mutating global os.environ directly inside worker threads",
    "Never mutate global os.environ state inside worker threads",
    "Do not mutate global os.environ variables inside worker threads",
    "Don't mutate global os.environ dictionary in worker threads",
)


@pytest.fixture
def review_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return _init_git_repo(tmp_path / "repo"), home


@pytest.mark.parametrize("decision", ["snooze", "reject", "propose", "merge-into-rule"])
def test_a_decided_cluster_leaves_the_review_and_only_snooze_or_reject_resurface(review_repo, decision):
    repo, home = review_repo
    first = [_hook_insight(repo, text, f"s-{i}", home)["id"] for i, text in enumerate(ENV_TEXTS[:2])]
    cluster, = review_insights(repo, home=home)["clusters"]
    assert sorted(cluster["insight_ids"]) == sorted(first)
    record_decision(repo, cluster_id=cluster["cluster_id"], decision=decision, insight_ids=cluster["insight_ids"],
                    reason="not now", home=home)
    hidden = review_insights(repo, home=home)
    assert hidden["clusters"] == []
    assert [sorted(c["insight_ids"]) for c in hidden["suppressed_clusters"]] == [sorted(first)]
    _hook_insight(repo, ENV_TEXTS[2], "s-2", home)
    assert review_insights(repo, home=home)["clusters"] == []
    _hook_insight(repo, ENV_TEXTS[3], "s-3", home)
    after = review_insights(repo, home=home)
    if decision in ("snooze", "reject"):
        assert [c["count"] for c in after["clusters"]] == [4]
    else:
        assert after["clusters"] == [] and [c["count"] for c in after["suppressed_clusters"]] == [4]


def test_a_confirmed_suggestion_counts_as_cli_and_an_unconfirmed_one_does_not(review_repo):
    repo, home = review_repo
    s1 = capture_suggestion(repo, ENV_TEXTS[1], paths=["src/app.py"], host="claude-code", session="agent", home=home)
    s2 = capture_suggestion(repo, "Prefer pathlib joins over string concatenation", paths=["src/app.py"],
                            host="claude-code", session="agent", home=home)
    assert review_insights(repo, home=home)["clusters"] == []
    record_decision(repo, decision="confirm", insight_ids=[s1["id"]], kind="concurrency", home=home)
    review = review_insights(repo, home=home)
    assert [(c["insight_ids"], c["levels"], c["kinds"]) for c in review["clusters"]] == [([s1["id"]], ["cli"], ["concurrency"])]
    assert [s["id"] for s in review["suggestions"]] == [s2["id"]]
    with pytest.raises(ValueError, match="verbatim"):
        write_proposal(repo, proposal_id="trap-env", insight_ids=[s1["id"]], summary_bullets=[ENV_TEXTS[1]], home=home)


def test_confirming_a_corroborated_suggestion_does_not_count_the_correction_twice(review_repo):
    repo, home = review_repo
    hook = _hook_insight(repo, ENV_TEXTS[1], "host-s", home)
    cap = capture_suggestion(repo, "mutate global os.environ state", paths=["src/app.py"], host="claude-code",
                             session="agent", home=home)
    record_decision(repo, decision="confirm", insight_ids=[cap["id"]], home=home)
    assert [(c["insight_ids"], c["corroborated"]) for c in review_insights(repo, home=home)["clusters"]] == [
        ([hook["id"]], [cap["id"]])]


def test_neighbours_are_emitted_once_per_insight(review_repo):
    repo, home = review_repo
    ids = [_hook_insight(repo, text, f"s-{i}", home)["id"] for i, text in enumerate(ENV_TEXTS[:2])]
    review = review_insights(repo, home=home)
    assert sorted(review["neighbours"]) == sorted(ids)
    assert all("neighbours" not in c for c in review["clusters"])


def test_record_decision_refuses_a_confirm_without_insights_and_a_missing_cluster(review_repo):
    repo, home = review_repo
    with pytest.raises(ValueError, match="insight"):
        record_decision(repo, decision="confirm", insight_ids=[], home=home)
    with pytest.raises(ValueError, match="cluster_id"):
        record_decision(repo, decision="snooze", insight_ids=["ins-1"], home=home)
    assert read_insight_rows(repo, home=home) == []


# ── R-evidence-41: recurrence over heartbeat-alive sessions, a rate at most 1, a baseline ──

RMTREE_BODY = "Always check path confinement before recursive directory removal."
RMTREE_TEXT = "stop calling recursive directory removal without path confinement check in src/app.py"


def _prompt(repo: Path, home: Path, session: str, text: str = "Please run the tests.") -> Dict[str, Any]:
    return record_hook_prompt(repo, "claude-code", {"prompt": text, "session_id": session, "cwd": str(repo)}, home=home)


def _recurrence_row(repo: Path, home: Path, hs: Any, when: str, rid: str = "trap-validate-rmtree") -> None:
    rev = load_rules(repo).get(rid).digest[:16]
    row = {"v": 1, "ts": when, "event": "insight", "id": f"ins-{os.urandom(6).hex()}", "level": "W2", "source": "hook",
           "text": RMTREE_TEXT, "paths": ["src/app.py"], "psrc": "dirty", "host": "claude-code", "revs": {rid: rev}}
    if hs:
        row["hs"] = hs
    append_jsonl(insights_path(repo, home=home), [row])


def _shift(stamp: str, seconds: int) -> str:
    from datetime import datetime, timedelta

    return (datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_three_episodes_in_one_alive_session_give_a_rate_of_at_most_one_and_the_alarm(review_repo):
    repo, home = review_repo
    _write_rule(repo, "trap-validate-rmtree", ["src/*.py"], RMTREE_BODY)
    hb = _prompt(repo, home, "s1")
    for k in range(3):
        _recurrence_row(repo, home, hb["hs"], _shift(hb["ts"], 600 * k))
    rec = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert (rec["sessions"], rec["recurrent_sessions"], rec["recurrences"]) == (1, 1, 3)
    assert rec["rate"] <= 1.0 and rec["rate"] == 1.0
    assert (rec["alarm"], rec["status"]) == (True, "not_working")
    assert 0.0 < rec["rate_ucb95"] <= 1.0


def test_recurrences_of_sessions_without_a_heartbeat_are_not_counted(review_repo):
    repo, home = review_repo
    _write_rule(repo, "trap-validate-rmtree", ["src/*.py"], RMTREE_BODY)
    hb = _prompt(repo, home, "s1")
    for k, hs in enumerate(("a" * 32, "b" * 32, "c" * 32)):
        _recurrence_row(repo, home, hs, _shift(hb["ts"], 600 * k))
    _recurrence_row(repo, home, None, hb["ts"])
    rec = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert (rec["sessions"], rec["recurrences"], rec["rate"], rec["alarm"]) == (1, 0, 0.0, False)
    assert rec["unattributed_recurrences"] == 1
    assert rec["denominator"] == "sessions = all heartbeat-alive sessions in this workspace (not scope-filtered)"


def test_the_baseline_excludes_the_burst_that_produced_the_rule(review_repo):
    repo, home = review_repo
    for f in (repo / ".aegis" / "rules" / "traps").glob("*.md"):
        f.unlink()
    burst = _hook_insight(repo, "No, " + RMTREE_TEXT, "s-a", home)
    _hook_insight(repo, "Stop calling recursive directory removal without a path confinement check", "s-b", home)
    _prompt(repo, home, "s-c")
    rule = _write_rule(repo, "trap-validate-rmtree", ["src/*.py"], RMTREE_BODY)
    rule.write_text(rule.read_text(encoding="utf-8").replace(
        "target_paths:", f'insight_ids:\n  - "{burst["id"]}"\ntarget_paths:'), encoding="utf-8")
    _prompt(repo, home, "s-d")
    rec = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert (rec["sessions"], rec["recurrences"]) == (1, 0)
    assert (rec["baseline_sessions"], rec["baseline_rate"]) == (3, round(1 / 3, 6))


def test_insight_born_rules_lists_served_rules_with_insight_ids(review_repo):
    from aegis_core.insights import insight_born_rules

    repo, home = review_repo
    _write_rule(repo, "trap-plain", ["src/*.py"], "Body.")
    born = _write_rule(repo, "trap-born", ["src/*.py"], "Body.")
    born.write_text(born.read_text(encoding="utf-8").replace("target_paths:", 'insight_ids:\n  - "ins-1"\ntarget_paths:'),
                    encoding="utf-8")
    assert [r.id for r in insight_born_rules(repo)] == ["trap-born"]


def test_a_row_without_an_id_is_reviewed_without_error(review_repo):
    repo, home = review_repo
    append_jsonl(insights_path(repo, home=home), [{
        "v": 1, "ts": "2026-10-20T00:00:00Z", "event": "insight", "level": "cli", "text": ENV_TEXTS[0],
        "paths": ["src/app.py"], "psrc": "explicit", "host": "cli"}])
    cluster, = review_insights(repo, home=home)["clusters"]
    assert (cluster["count"], cluster["levels"]) == (1, ["cli"])


# ── R-evidence-44: the closed proposal template ──────────────────────────────

def _frontmatter(path: Path) -> Dict[str, Any]:
    from aegis_core.yaml_engine.frontmatter import parse_frontmatter

    return parse_frontmatter(path.read_text(encoding="utf-8"))


def _confirmed_group(repo: Path, home: Path, paths_per_member, kind: str = "api-validation") -> list:
    ids = [capture_suggestion(repo, f"Validate request bodies at the boundary, case {n}", paths=paths,
                              host="claude-code", session="agent", home=home)["id"]
           for n, paths in enumerate(paths_per_member)]
    record_decision(repo, decision="confirm", insight_ids=ids, kind=kind, home=home)
    return ids


def test_a_proposal_names_its_kind_count_ids_and_the_idf_weighted_common_directory(review_repo):
    """Given a confirmed group of 3 insights under src/api/ and two unrelated insights elsewhere
    under src/, When a proposal is written, Then it is a trap/advisory with the group's kind, a
    count of 3, its ids and target_paths src/api/** (src/ is common to more insights, so it
    weighs less), and no category."""
    repo, home = review_repo
    for n in range(2):
        add_insight(repo, f"Keep the helper module small, note {n}", paths=["src/util.py"], home=home)
    ids = _confirmed_group(repo, home, [["src/api/a.py"], ["src/api/b.py"], ["src/api/a.py", "src/api/b.py"]])
    meta = _frontmatter(write_proposal(repo, proposal_id="trap-api-bodies", insight_ids=ids, home=home))
    assert (meta["type"], meta["enforcement"], meta["kind"], meta["count"]) == ("trap", "advisory", "api-validation", 3)
    assert meta["insight_ids"] == ids and meta["target_paths"] == ["src/api/**"]
    assert "category" not in meta


def test_members_in_separate_directories_get_one_prefix_each_and_a_top_level_file_stands_for_itself(review_repo):
    repo, home = review_repo
    ids = _confirmed_group(repo, home, [["src/api/a.py"], ["src/api/b.py"], ["lib/x.py"], ["setup.py"]])
    meta = _frontmatter(write_proposal(repo, proposal_id="trap-spread", insight_ids=ids, home=home))
    assert meta["target_paths"] == ["src/api/**", "lib/**", "setup.py"]
    assert meta["count"] == 4


def test_a_group_without_paths_asks_for_them_and_writes_nothing(review_repo):
    repo, home = review_repo
    ids = _confirmed_group(repo, home, [None, None])
    with pytest.raises(ValueError, match="--paths"):
        write_proposal(repo, proposal_id="trap-nowhere", insight_ids=ids, home=home)
    assert not (repo / ".aegis" / "proposals").exists()


def test_a_group_without_one_kind_needs_an_explicit_kind(review_repo):
    repo, home = review_repo
    first = add_insight(repo, "Close every file handle you open", paths=["src/app.py"], kind="resources", home=home)
    second = add_insight(repo, "Close sockets on every error path", paths=["src/app.py"], kind="network", home=home)
    with pytest.raises(ValueError, match="--kind"):
        write_proposal(repo, proposal_id="trap-close", insight_ids=[first["id"], second["id"]], home=home)
    assert not (repo / ".aegis" / "proposals").exists()
    path = write_proposal(repo, proposal_id="trap-close", insight_ids=[first["id"], second["id"]], kind="resources",
                          home=home)
    assert _frontmatter(path)["kind"] == "resources"


def test_an_unconfirmed_suggestion_or_an_unknown_id_never_enters_a_proposal(review_repo):
    repo, home = review_repo
    kept = add_insight(repo, "Close every file handle you open", paths=["src/app.py"], kind="resources", home=home)
    agent = capture_suggestion(repo, "Close every file handle", paths=["src/app.py"], host="claude-code",
                               session="agent", home=home)
    for extra in (agent["id"], "ins-000000000000"):
        with pytest.raises(ValueError, match="not a counted insight"):
            write_proposal(repo, proposal_id="trap-close", insight_ids=[kept["id"], extra], home=home)
    assert not (repo / ".aegis" / "proposals").exists()


# ── review M1: the signed re-run of a cli insight counts once ──────────────────

SIGNED_TEXT = "Never call subprocess.Popen without a timeout in the cli modules"


def _signed_rerun(repo: Path, home: Path, row: Dict[str, Any], **changes: Any) -> Dict[str, Any]:
    """The H row ``insight add --commit SHA`` appends for ``row``'s typed text; the signature
    itself is the signed-commit tests' subject."""
    h_row = {**row, "id": f"ins-{os.urandom(6).hex()}", "level": "H", **changes}
    append_jsonl(insights_path(repo, home=home), [h_row])
    return h_row


def _counted_ids(repo: Path, home: Path) -> list:
    return sorted(i for c in review_insights(repo, home=home)["clusters"] for i in c["insight_ids"])


def test_a_signed_rerun_supersedes_its_cli_row_in_review_and_proposals(review_repo):
    """Given `insight add T` (cli) and the documented re-run with --commit (H, same text, paths
    and kind), When the insights are reviewed and proposed, Then one correction counts once: the
    H row, and the superseded cli row is not a counted insight."""
    repo, home = review_repo
    cli = add_insight(repo, SIGNED_TEXT, paths=["src/app.py"], kind="timeouts", home=home)
    signed = _signed_rerun(repo, home, cli)
    cluster, = review_insights(repo, home=home)["clusters"]
    assert (cluster["count"], cluster["insight_ids"], cluster["levels"]) == (1, [signed["id"]], ["H"])
    with pytest.raises(ValueError, match=f"not a counted insight: {cli['id']}"):
        write_proposal(repo, proposal_id="trap-popen", insight_ids=[cli["id"], signed["id"]], home=home)
    assert not (repo / ".aegis" / "proposals").exists()
    meta = _frontmatter(write_proposal(repo, proposal_id="trap-popen", insight_ids=cluster["insight_ids"], home=home))
    assert (meta["count"], meta["insight_ids"]) == (1, [signed["id"]])


def test_two_identical_cli_adds_without_a_signed_rerun_still_count_twice(review_repo):
    """Sad path: with no H row nothing is superseded, so two identical cli adds count as two, as
    before (a cli row carries no session, so they are one unattributed recurrence episode)."""
    repo, home = review_repo
    ids = sorted(add_insight(repo, SIGNED_TEXT, paths=["src/app.py"], kind="timeouts", home=home)["id"]
                 for _ in range(2))
    cluster, = review_insights(repo, home=home)["clusters"]
    assert (cluster["count"], sorted(cluster["insight_ids"])) == (2, ids)
    assert _frontmatter(write_proposal(repo, proposal_id="trap-popen", insight_ids=ids, home=home))["count"] == 2


@pytest.mark.parametrize("changes", [
    {"text": "Always pass an explicit timeout to every subprocess call in the cli"},
    {"paths": ["src/other.py"]},
    {"kind": "processes"},
], ids=["text", "paths", "kind"])
def test_an_h_row_that_differs_supersedes_nothing(review_repo, changes):
    repo, home = review_repo
    cli = add_insight(repo, SIGNED_TEXT, paths=["src/app.py"], kind="timeouts", home=home)
    signed = _signed_rerun(repo, home, cli, **changes)
    assert _counted_ids(repo, home) == sorted([cli["id"], signed["id"]])


def test_an_h_row_supersedes_only_the_cli_adds_before_it(review_repo):
    repo, home = review_repo
    first = add_insight(repo, SIGNED_TEXT, paths=["src/app.py"], kind="timeouts", home=home)
    signed = _signed_rerun(repo, home, first)
    later = add_insight(repo, SIGNED_TEXT, paths=["src/app.py"], kind="timeouts", home=home)
    assert _counted_ids(repo, home) == sorted([signed["id"], later["id"]])


def test_a_signed_rerun_is_one_recurrence_not_two(review_repo):
    """Given a cli insight matching an insight-born rule and its H re-run an hour later (two
    episodes if both counted), When recurrence is measured, Then it is one unattributed episode."""
    repo, home = review_repo
    _write_rule(repo, "trap-validate-rmtree", ["src/*.py"], RMTREE_BODY)
    cli = add_insight(repo, RMTREE_TEXT, paths=["src/app.py"], home=home)
    _signed_rerun(repo, home, cli, ts=_shift(cli["ts"], 3600))
    rec = measure_recurrence(repo, "trap-validate-rmtree", home=home)
    assert (rec["recurrences"], rec["unattributed_recurrences"]) == (0, 1)
