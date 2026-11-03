#!/usr/bin/env python3
"""Bounded model-free watch service over the canonical lifecycle ledger.

The SQLite store contains watch dispatch references, never execution authority or
another lifecycle ledger. Native CLI execution is held. Fake host qualification
uses the explicit public bridge port and evidence-only stores.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (SLUG, digest, encoded, integer, matching, publish_file, read_json,  # noqa: E402
                               require, safe_path, timestamp)
from hierarchy_watch_bridge import NativeBridge  # noqa: E402


MAX_ATTEMPTS = 10000
MAX_HISTORY = 40000
MUTATION_HOLD = "mutation requires --evidence-only; native service is unqualified"


class LifecycleUnavailable(ValueError):
    """A failed observation is retained as HOLD, never permission to dispatch."""


def lifecycle_status(path):
    try:
        from hierarchy_lifecycle import Lifecycle
        return Lifecycle(path).status()
    except (ImportError, OSError, ValueError, UnicodeError, KeyError, TypeError) as exc:
        raise LifecycleUnavailable("lifecycle unavailable: " + str(exc)) from exc


def initialize(root, lifecycle_root, watch_id, *, evidence_only=False):
    require(evidence_only is True, MUTATION_HOLD)
    require(os.name == "posix", "watch worker locking requires POSIX")
    root, lifecycle_root = safe_path(root), safe_path(lifecycle_root)
    matching(watch_id, SLUG, "watch id")
    lifecycle_status(lifecycle_root)
    require(not root.exists(), "watch root already exists")
    root.mkdir(mode=0o700)
    config = {"schema": "aegis.watch-config/v1", "watch_id": watch_id,
              "lifecycle_root": str(lifecycle_root), "evidence_only": True}
    publish_file(root / "config.json", encoded(config) + b"\n")
    with sqlite3.connect(str(root / "watch.sqlite")) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.executescript("""
            CREATE TABLE control (config_sha256 TEXT NOT NULL, generation INTEGER NOT NULL,
                                  iterations INTEGER NOT NULL, holds TEXT NOT NULL);
            CREATE TABLE attempts (operation_id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                                   request_sha256 TEXT NOT NULL, generation INTEGER NOT NULL,
                                   state TEXT NOT NULL, result TEXT NOT NULL);
            CREATE TABLE history (sequence INTEGER PRIMARY KEY, operation_id TEXT NOT NULL,
                                  state TEXT NOT NULL, record TEXT NOT NULL);
        """)
        db.execute("INSERT INTO control VALUES (?, 1, 0, '{}')", (digest(config),))
    descriptor = os.open(root, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return Supervisor(root).status()


class Supervisor:
    def __init__(self, root):
        self.root = safe_path(root)
        self.config = read_json(self.root / "config.json")
        require(set(self.config) == {"schema", "watch_id", "lifecycle_root", "evidence_only"}, "invalid watch config fields")
        require(self.config["schema"] == "aegis.watch-config/v1" and self.config["evidence_only"] is True,
                "unsupported watch config")
        matching(self.config["watch_id"], SLUG, "watch id")
        self.lifecycle_root = safe_path(self.config["lifecycle_root"])

    @contextmanager
    def database(self, *, readonly=False):
        path = safe_path(self.root / "watch.sqlite")
        mode = "ro" if readonly else "rw"
        db = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=1)
        db.row_factory = sqlite3.Row
        try:
            if not readonly:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM control").fetchall()
            require(len(rows) == 1 and rows[0]["config_sha256"] == digest(self.config), "watch config digest mismatch")
            yield db
            if not readonly:
                db.commit()
        finally:
            db.close()

    @contextmanager
    def worker(self):
        require(os.name == "posix", "watch worker locking requires POSIX")
        import fcntl
        path = safe_path(self.root / "worker.lock")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("watch worker is already active") from exc
            yield
        finally:
            os.close(fd)

    @staticmethod
    def fence(db, generation):
        integer(generation, "watch generation")
        require(db.execute("SELECT generation FROM control").fetchone()[0] == generation, "watch generation is fenced")

    @staticmethod
    def history(db, operation_id, state, record):
        require(db.execute("SELECT COUNT(*) FROM history").fetchone()[0] < MAX_HISTORY, "watch history limit reached")
        db.execute("INSERT INTO history(operation_id,state,record) VALUES (?,?,?)",
                   (operation_id, state, encoded({"at": timestamp(), **record}).decode()))

    def advance(self, expected_generation, next_generation):
        integer(next_generation, "next generation")
        require(next_generation == expected_generation + 1, "watch generation must advance by one")
        with self.worker(), self.database() as db:
            self.fence(db, expected_generation)
            db.execute("UPDATE control SET generation=?", (next_generation,))
            self.history(db, "generation", "fenced", {"previous": expected_generation, "generation": next_generation})
        return self.status()

    def status(self):
        observation_error = None
        try:
            lifecycle = lifecycle_status(self.lifecycle_root)
        except LifecycleUnavailable as exc:
            observation_error = str(exc)
            lifecycle = {"obligations": [], "continuation_holds": {}, "head": None, "work_complete": False}
        with self.database(readonly=True) as db:
            control = db.execute("SELECT * FROM control").fetchone()
            attempts = [{**dict(row), "result": json.loads(row["result"])}
                        for row in db.execute("SELECT * FROM attempts ORDER BY rowid")]
            history = [{**dict(row), "record": json.loads(row["record"])}
                       for row in db.execute("SELECT * FROM history ORDER BY sequence")]
        pending = {row["request_id"] for row in lifecycle["obligations"]}
        holds = {key: value for key, value in json.loads(control["holds"]).items() if key in pending}
        holds.update(lifecycle["continuation_holds"])
        for attempt in attempts:
            row = lifecycle.get("requests", {}).get(attempt["request_id"])
            terminal = row["terminal"] if row else None
            # Derive settlement from the one canonical intent/result. Keep the
            # original watch failure and history intact; never infer acceptance.
            attempt["canonical_settlement"] = None
            if (row and row["raw"]["sha256"] == attempt["request_sha256"] and terminal
                    and terminal["value"]["outcome"] != "unknown"):
                attempt["canonical_settlement"] = {"intent_id": row["intent"]["id"],
                                                   "terminal_sha256": terminal["sha256"]}
        unresolved = any(row["state"] in {"dispatching", "unknown"} and row["canonical_settlement"] is None
                         for row in attempts)
        return {"schema": "aegis.watch-status/v1", "watch_id": self.config["watch_id"],
                "state": "hold" if observation_error else "observed", "observation_error": observation_error,
                "generation": control["generation"], "iterations": control["iterations"],
                "attempts": attempts, "history": history, "holds": holds,
                "obligations": lifecycle["obligations"], "lifecycle_head": lifecycle["head"],
                "work_complete": lifecycle["work_complete"] and not unresolved,
                "native_qualified": False, "execution_enabled": False, "evidence_only": True}

    def step(self, generation, bridge=None):
        with self.worker():
            return self._step(generation, bridge or NativeBridge())

    def _step(self, generation, bridge, *, deadline=None, stop_event=None):
        if (deadline is not None or stop_event is not None) and hasattr(bridge, "with_control"):
            bridge = bridge.with_control(deadline=deadline, stop_event=stop_event)

        def may_continue():
            return ((deadline is None or time.monotonic() < deadline)
                    and (stop_event is None or not stop_event.is_set()))

        with self.database() as db:
            self.fence(db, generation)
        lifecycle = lifecycle_status(self.lifecycle_root)
        holds = dict(lifecycle["continuation_holds"])
        for request_id in lifecycle["continuation_candidates"]:
            if not may_continue():
                break
            request_sha256 = lifecycle["requests"][request_id]["raw"]["sha256"]
            operation_id = "watch-" + digest({"request_id": request_id, "request_sha256": request_sha256})
            with self.database(readonly=True) as db:
                prior = db.execute("SELECT state,result FROM attempts WHERE operation_id=?", (operation_id,)).fetchone()
            if prior and not (prior["state"] == "refused" and json.loads(prior["result"]).get("effect") == "none"):
                holds[request_id] = "watch dispatch already recorded; canonical settlement required"
                continue
            if not may_continue():
                break
            try:
                observed = bridge.observe(request_id, request_sha256)
            except (OSError, subprocess.SubprocessError) as exc:
                # Observation is read-only by contract. Reconnecting may obtain
                # a new sample, but cannot authorize retrying a dispatched effect.
                holds[request_id] = "host observation unavailable: " + str(exc)[:4096]
                with self.database() as db:
                    self.fence(db, generation)
                    self.history(db, operation_id, "observation_hold", {"request_id": request_id,
                                 "error": holds[request_id]})
                continue
            require(isinstance(observed, dict) and observed.get("state") in {"eligible", "hold"}
                    and type(observed.get("native_qualified")) is bool, "invalid bridge observation")
            if observed["state"] == "hold":
                holds[request_id] = str(observed.get("reason", "bridge held"))[:4096]
                continue
            # Re-read after external observation. Operator also rechecks the
            # canonical source/authority/identity immediately before its effect.
            current = lifecycle_status(self.lifecycle_root)
            if (request_id not in current["continuation_candidates"]
                    or current["requests"][request_id]["raw"]["sha256"] != request_sha256):
                holds[request_id] = "canonical eligibility changed during observation"
                continue
            with self.database() as db:
                self.fence(db, generation)
                if not may_continue():
                    break
                require(db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] < MAX_ATTEMPTS or prior is not None,
                        "watch attempt limit reached")
                db.execute("INSERT OR REPLACE INTO attempts VALUES (?,?,?,?,?,?)",
                           (operation_id, request_id, request_sha256, generation, "dispatching", "{}"))
                self.history(db, operation_id, "dispatching", {"request_id": request_id,
                             "request_sha256": request_sha256, "generation": generation})
            try:
                if may_continue():
                    result = bridge.continue_request(request_id, request_sha256, operation_id)
                else:
                    # Commit/fsync may outlast the remaining budget. No provider
                    # call occurred, so this retained dispatch is a known refusal.
                    result = {"state": "refused", "effect": "none", "native_qualified": False,
                              "reason": "watch stopped or deadline reached before provider dispatch"}
                require(isinstance(result, dict) and result.get("state") in {"completed", "refused", "unknown"},
                        "invalid bridge result state")
                require(result.get("effect") == {"completed": "confirmed", "refused": "none", "unknown": "possible"}[result["state"]],
                        "invalid bridge result effect")
                require(result.get("native_qualified") is False, "evidence-only watch cannot certify native execution")
                encoded(result)
            except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
                result = {"state": "unknown", "effect": "possible", "reason": str(exc)[:4096], "native_qualified": False}
            with self.database() as db:
                self.fence(db, generation)
                db.execute("UPDATE attempts SET state=?,result=? WHERE operation_id=?",
                           (result["state"], encoded(result).decode(), operation_id))
                self.history(db, operation_id, result["state"], result)
        with self.database() as db:
            self.fence(db, generation)
            db.execute("UPDATE control SET iterations=iterations+1, holds=?", (encoded(holds).decode(),))
        return self.status()

    def run(self, generation, *, seconds, interval=1, bridge=None, stop_event=None):
        require(type(seconds) in (int, float) and 0 < seconds <= 3600, "invalid run seconds")
        require(type(interval) in (int, float) and 0.01 <= interval <= 60, "invalid poll interval")
        stop_event = stop_event or threading.Event()
        deadline = time.monotonic() + seconds
        with self.worker():
            while not stop_event.is_set() and time.monotonic() < deadline:
                try:
                    self._step(generation, bridge or NativeBridge(), deadline=deadline, stop_event=stop_event)
                except LifecycleUnavailable as exc:
                    # Keep polling, but retain the exact failed observation and
                    # perform no dispatch based on it. Never repair the ledger.
                    with self.database() as db:
                        self.fence(db, generation)
                        self.history(db, "observation", "observation_hold", {"error": str(exc)[:4096]})
                stop_event.wait(max(0, min(interval, deadline - time.monotonic())))
        return self.status()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--lifecycle", required=True)
    init.add_argument("--watch-id", required=True)
    init.add_argument("--evidence-only", action="store_true")
    commands.add_parser("status")
    for name in ("step", "run", "advance"):
        command = commands.add_parser(name)
        command.add_argument("--generation", type=int, required=True)
        command.add_argument("--evidence-only", action="store_true")
        if name == "run":
            command.add_argument("--seconds", type=float, required=True)
            command.add_argument("--interval", type=float, default=1)
        elif name == "advance":
            command.add_argument("--next-generation", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        root = safe_path(args.root)
        if args.command != "status":
            require(args.evidence_only, MUTATION_HOLD)
        if args.command == "init":
            result = initialize(root, args.lifecycle, args.watch_id, evidence_only=True)
        elif args.command == "status":
            result = Supervisor(root).status()
        elif args.command == "step":
            result = Supervisor(root).step(args.generation)
        elif args.command == "advance":
            result = Supervisor(root).advance(args.generation, args.next_generation)
        else:
            stop = threading.Event()
            signal.signal(signal.SIGTERM, lambda _signum, _frame: stop.set())
            signal.signal(signal.SIGINT, lambda _signum, _frame: stop.set())
            result = Supervisor(root).run(args.generation, seconds=args.seconds, interval=args.interval, stop_event=stop)
    except (ValueError, OSError, sqlite3.Error, UnicodeError, TypeError, KeyError) as exc:
        print(encoded({"state": "hold", "error": str(exc), "work_complete": False,
                       "native_qualified": False, "execution_enabled": False}).decode())
        return 2
    print(encoded(result).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
