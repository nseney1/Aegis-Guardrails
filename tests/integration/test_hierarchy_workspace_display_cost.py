"""Display work is failure-only and bounded by distinct response strings."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import hierarchy_workspace as controller
import hierarchy_workspace_display as display
from tests.conftest import symlink_or_skip
from tests.integration.test_hierarchy_workspace import memo_store


AT = "2026-11-16T00:00:00Z"
REGISTER = {"id": "a1", "project": "aegis", "repository": "aegis", "priority": 1,
            "target_branch": "develop", "lanes": ["lane"]}
REQUEST = {"request_id": "req-00000003", "initiative": "a1", "kind": "writer", "holder": "worker"}
EVIDENCE = {"path": str(Path(__file__).resolve()), "sha256": "a" * 64}


def fingerprint(value):
    raw = value.encode("utf-8", errors="surrogatepass")
    return "<redacted len=%d sha256=%s>" % (len(value), hashlib.sha256(raw).hexdigest()[:12])


def write_history(tmp_path, rows):
    store = controller.Store(tmp_path / "store")
    store.events.mkdir(parents=True)
    for seq, (kind, data) in enumerate(rows, 1):
        event = {"schema": controller.EVENT_SCHEMA, "seq": seq, "at": AT, "kind": kind, "data": data}
        (store.events / ("%08d.json" % seq)).write_text(json.dumps(event), encoding="utf-8")
    return store


def initial_rows():
    return [("init", {"writer_limit": 3, "heavy_limit": 1}), ("register", dict(REGISTER))]


def count_displays(monkeypatch):
    calls = []
    original = display._display

    def counted(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(controller, "_display", counted)
    monkeypatch.setattr(display, "_display", counted)
    return calls


@pytest.mark.parametrize("portable", [False, True], ids=["cached", "portable"])
def test_ten_thousand_event_cold_and_warm_replay_never_displays(tmp_path, monkeypatch, portable):
    if portable:
        monkeypatch.setattr(controller, "_memo_supported", lambda: False)
    else:
        memo_store(SimpleNamespace(store=tmp_path / "store"))
    rows = initial_rows()
    for seq in range(3, 10001):
        offset = (seq - 3) % 3
        identifier = "req-%08d" % (seq - offset)
        rows.append(("request", {**REQUEST, "request_id": identifier}) if offset == 0 else
                    ("grant", {"request_id": identifier}) if offset == 1 else
                    ("release", {"request_id": identifier, "evidence": EVIDENCE}))
    store = write_history(tmp_path, rows)
    calls = count_displays(monkeypatch)
    cold = store.load()
    cold_calls = len(calls)
    calls.clear()
    warm = store.load()
    assert cold.seq == warm.seq == 10000
    assert cold.requests == warm.requests
    assert (store._memo is None) == portable
    assert (cold_calls, len(calls)) == (0, 0)


def test_valid_transitions_append_and_retry_never_display(tmp_path, monkeypatch):
    store = write_history(tmp_path, initial_rows())
    calls = count_displays(monkeypatch)
    ledger = store.load()
    transitions = [("request", REQUEST), ("withdraw", {"request_id": REQUEST["request_id"], "source": "fixture"}),
                   ("register", {**REGISTER, "id": "peer", "lanes": ["other"]}),
                   ("set_limits", {"writer_limit": 2, "source": "fixture"})]
    for kind, data in transitions:
        with store.lock():
            store.append(ledger, kind, data)
        assert store.load().seq == ledger.seq
        assert store.load().seq == ledger.seq
    assert len(calls) == 0


@pytest.mark.parametrize("site", ["fields", "initiative", "request", "kind", "lanes", "withdraw", "grant",
                                  "release", "unexpected", "sequence"])
def test_refusal_site_keeps_exact_cli_bytes_on_retry(tmp_path, capsys, site):
    rows = initial_rows()
    raw = "bad\nvalue"
    shown = fingerprint(raw)
    prefix = None
    if site == "fields":
        rows.append(("register", {**REGISTER, raw: True}))
        error = "unexpected fields: " + shown
    elif site == "initiative":
        rows.append(("update", {"initiative": raw, "source": "fixture"}))
        error = "initiative is not registered: " + shown
    elif site == "request":
        rows.append(("withdraw", {"request_id": raw, "source": "fixture"}))
        error = "unknown request: " + shown
    elif site == "kind":
        rows.append((raw, {}))
        error = "unknown workspace event: " + shown
    elif site == "lanes":
        rows[1][1]["lanes"] = [raw]
        rows.append(("register", {**REGISTER, "id": "peer", "lanes": [raw]}))
        error = "lane already belongs to initiative a1: " + shown
    elif site in ("withdraw", "grant", "release"):
        rows.append(("request", REQUEST))
        if site == "withdraw":
            rows.append(("grant", {"request_id": REQUEST["request_id"]}))
        elif site == "grant":
            rows.append(("withdraw", {"request_id": REQUEST["request_id"], "source": "fixture"}))
        rows.append((site, {"request_id": REQUEST["request_id"], **(
            {"source": "fixture"} if site == "withdraw" else {"evidence": EVIDENCE} if site == "release" else {})}))
        error = ("request is not granted: " if site == "release" else "request is not queued: ") + REQUEST["request_id"]
    store = write_history(tmp_path, rows)
    if site == "unexpected":
        (store.events / "unexpected.json").write_text("{}", encoding="utf-8")
        error = "unexpected workspace store entry: unexpected.json"
    elif site == "sequence":
        (store.events / "00000002.json").rename(store.events / "00000003.json")
        error = "nonconsecutive workspace event: 00000003.json"
    else:
        path = store.events / ("%08d.json" % len(rows))
        # This slot displays a Path; the raw path is still fingerprinted in full.
        prefix = "malformed workspace event: " + display._display(path) + ": "
    expected = json.dumps({"error": (prefix or "") + error}, sort_keys=True) + "\n"
    for _ in range(2):
        assert controller.main(["--store", str(store.path), "status"]) == 2
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == expected


def test_symlink_refusal_keeps_exact_cli_bytes(tmp_path, capsys):
    store = write_history(tmp_path, initial_rows())
    memo_store(SimpleNamespace(store=store.path))
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    linked = store.events / "00000003.json"
    symlink_or_skip(target, linked)
    for _ in range(2):
        assert controller.main(["--store", str(store.path), "status"]) == 2
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == json.dumps({"error": "symlink paths are not supported: " + display._display(linked)},
                                          sort_keys=True) + "\n"


def conflict_ledger():
    ledger = controller.Ledger()
    ledger.initiatives["a1"] = {**REGISTER, "state": "active", "checkouts": ["/fixture"], "touched_paths": []}
    return ledger


def test_conflict_screens_each_distinct_string_once_per_response(monkeypatch):
    ledger = conflict_ledger()
    match, team, paths = controller.lease_tools()
    values = [("src/%03d/" % index).ljust(256, "x") for index in range(100)]
    scope = paths.stored_paths(values)
    leases = [SimpleNamespace(lane="lane-%03d" % index, oid="a" * 40, owner="owner", paths=values,
                              path_set=scope, expired=lambda now: False, expires_at=123) for index in range(100)]
    reader = SimpleNamespace(read_leases=lambda checkout: SimpleNamespace(leases=leases, unreadable=[]))
    monkeypatch.setattr(controller, "lease_tools", lambda: (match, reader, paths))
    calls = count_displays(monkeypatch)
    distinct = set(values) | {lease.lane for lease in leases} | {"owner", "/fixture"}
    for _ in range(2):
        calls.clear()
        code, result = controller.check_paths(ledger, "a1", values)
        assert code == 3 and result["paths"] == values
        assert len(result["conflicts"]) == 100
        assert all(row["paths"] == values for row in result["conflicts"])
        assert len(calls) <= len(distinct)
        assert set(calls) == distinct


@pytest.mark.parametrize("trusted_first", [False, True])
def test_response_cache_checks_each_fields_trust_before_reuse(monkeypatch, trusted_first):
    # SLUG permits this synthetic credential spelling, but an untrusted owner must hide it.
    value = "ghp_" + "a" * 20
    pairs = [("initiative", value), ("owner", value)]
    if not trusted_first:
        pairs.reverse()
    response = display._display_response(lambda: (3, dict(pairs)))
    calls = count_displays(monkeypatch)
    assert response() == (3, {"initiative": value, "owner": fingerprint(value)})
    assert calls == [value]


def test_response_caches_are_isolated_across_retries_and_concurrent_calls(monkeypatch):
    value = "token=" + "SYNTHETIC_VALUE"
    response = display._display_response(lambda: (3, {"owner": value, "paths": [value] * 100}))
    calls = count_displays(monkeypatch)
    with ThreadPoolExecutor(max_workers=3) as workers:
        futures = [workers.submit(response) for _ in range(6)]
        results = [future.result(timeout=10) for future in futures]
    expected = (3, {"owner": fingerprint(value), "paths": [fingerprint(value)] * 100})
    assert results == [expected] * 6
    assert calls == [value] * 6
    assert response() == expected
    assert calls == [value] * 7


def test_success_response_does_not_display(monkeypatch):
    value = {"owner": "token=" + "SYNTHETIC_VALUE"}
    response = display._display_response(lambda: (0, value))
    calls = count_displays(monkeypatch)
    assert response() == (0, value)
    assert calls == []


def test_require_keeps_string_contract_and_defers_callable_diagnostics():
    calls = []

    def diagnostic():
        calls.append("built")
        return "fixed refusal: a1"

    assert display.require(True, diagnostic) is None
    assert calls == []
    for message in ("fixed refusal: a1", diagnostic):
        with pytest.raises(controller._Refusal, match="^fixed refusal: a1$") as error:
            display.require(False, message)
        assert error.value.message == "fixed refusal: a1"
    assert calls == ["built"]


def test_failed_screening_does_not_pollute_the_next_response(monkeypatch):
    original = display._display
    attempts = []
    value = "token=" + "SYNTHETIC_VALUE"

    def screen(raw):
        attempts.append(raw)
        if len(attempts) == 1:
            raise ValueError("fixture screening failure")
        return original(raw)

    monkeypatch.setattr(display, "_display", screen)
    response = display._display_response(lambda: (3, {"owner": value, "paths": [value]}))
    with pytest.raises(ValueError, match="^fixture screening failure$"):
        response()
    assert response() == (3, {"owner": fingerprint(value), "paths": [fingerprint(value)]})
    assert attempts == [value, value]
