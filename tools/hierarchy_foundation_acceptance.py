#!/usr/bin/env python3
"""Replay reviewed reconstructed legacy fixtures; coupled acceptance remains held."""
from __future__ import annotations

import argparse
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile


MANIFEST_SHA256 = "f708a079afdb19edbf7ffa236956936e88a43b5114c75ccdbca9da757b7e2595"
MAILBOX_SHA256 = "5427e46a65f109257cbfb8153dee9e29384fe1908aa516708ede776f33f3add8"
MAX_FILE = 1048576
MAX_TOTAL = 4194304
SHA = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}\Z")
_REPLAY_MODULES = {}
sys.dont_write_bytecode = True


class AcceptanceError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code="FOUNDATION_CORPUS_INVALID"):
    if not condition:
        raise AcceptanceError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def read_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid_constant(value):
        raise AcceptanceError("FOUNDATION_CORPUS_INVALID")

    def depth(value, level=0):
        require(level <= 16)
        if isinstance(value, dict):
            for item in value.values():
                depth(item, level + 1)
        elif isinstance(value, list):
            for item in value:
                depth(item, level + 1)

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
        depth(value)
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AcceptanceError("FOUNDATION_CORPUS_INVALID") from exc


def relative(name):
    require(type(name) is str and 0 < len(name) <= 200, "FOUNDATION_CORPUS_PATH_INVALID")
    require(not any(c in name for c in ("\\", "\0", ":")), "FOUNDATION_CORPUS_PATH_INVALID")
    require(not PurePosixPath(name).is_absolute()
            and all(part not in ("", ".", "..") for part in name.split("/")),
            "FOUNDATION_CORPUS_PATH_INVALID")
    return name


def checked_root(value):
    try:
        root = Path(value).absolute()
    except (TypeError, ValueError) as exc:
        raise AcceptanceError("FOUNDATION_CORPUS_PATH_INVALID") from exc
    require(".." not in root.parts, "FOUNDATION_CORPUS_PATH_INVALID")
    require(not any(path.is_symlink() for path in (root, *root.parents)),
            "FOUNDATION_CORPUS_PATH_INVALID")
    return root


def read_file(root, name, limit=MAX_FILE):
    path = root / relative(name)
    require(not any(p.is_symlink() for p in (path, *path.parents)), "FOUNDATION_CORPUS_PATH_INVALID")
    try:
        info = path.stat()
        require(stat.S_ISREG(info.st_mode), "FOUNDATION_CORPUS_PATH_INVALID")
        require(info.st_size <= limit, "FOUNDATION_CORPUS_TOO_LARGE")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except FileNotFoundError as exc:
        raise AcceptanceError("FOUNDATION_CORPUS_MISSING") from exc
    except OSError as exc:
        raise AcceptanceError("FOUNDATION_CORPUS_INVALID") from exc
    require(len(raw) <= limit, "FOUNDATION_CORPUS_TOO_LARGE")
    return raw


def corpus_names(root):
    pending, files, visited = [root], set(), 0
    while pending:
        folder = pending.pop()
        try:
            for path in folder.iterdir():
                visited += 1
                require(visited <= 128, "FOUNDATION_CORPUS_TOO_LARGE")
                name = relative(path.relative_to(root).as_posix())
                require(not path.is_symlink(), "FOUNDATION_CORPUS_PATH_INVALID")
                if path.is_dir():
                    pending.append(path)
                else:
                    require(path.is_file(), "FOUNDATION_CORPUS_PATH_INVALID")
                    files.add(name)
                    require(len(files) <= 33, "FOUNDATION_CORPUS_TOO_LARGE")
        except OSError as exc:
            raise AcceptanceError("FOUNDATION_CORPUS_INVALID") from exc
    return files


def manifest(raw):
    value = read_json(raw)
    exact(value, {"schema", "provenance", "source_files", "files", "legacy_cases", "matrix"})
    require(value["schema"] == "aegis.foundation-corpus/v1")
    exact(value["provenance"], {"kind", "reference_commit", "reference_tests", "historical_execution_captured"})
    require(value["provenance"]["kind"] == "reconstructed_legacy_fixture"
            and value["provenance"]["historical_execution_captured"] is False)
    for key in ("files", "source_files"):
        require(type(value[key]) is dict and 0 < len(value[key]) <= 32)
        for name, sha in value[key].items():
            relative(name)
            require(type(sha) is str and SHA.fullmatch(sha))
    relative(value["matrix"])
    require(value["matrix"] in value["files"])
    cases = value["legacy_cases"]
    require(type(cases) is list and 0 < len(cases) <= 4)
    identities = set()
    for case in cases:
        exact(case, {"case_id", "prefix", "request_id", "receipt_id", "expected_operator",
                     "expected_intent", "expected_sequence"})
        for key in ("case_id", "request_id", "receipt_id", "expected_operator"):
            require(type(case[key]) is str and ID.fullmatch(case[key]))
        relative(case["prefix"])
        require(case["expected_intent"] is None or (type(case["expected_intent"]) is str
                                                    and ID.fullmatch(case["expected_intent"])))
        require(type(case["expected_sequence"]) is int and 1 <= case["expected_sequence"] <= 16)
        require(case["case_id"] not in identities)
        identities.add(case["case_id"])
    # The caller cannot supply a new oracle or a different dependency source map.
    require(digest(raw) == MANIFEST_SHA256, "FOUNDATION_MANIFEST_MISMATCH")
    return value


class _VerifiedSourceLoader(importlib.abc.SourceLoader):
    """Load only the already verified source snapshot, without bytecode reads."""

    def __init__(self, name, path, raw):
        self.name, self.path, self.raw = name, str(path), raw

    def get_filename(self, fullname):
        require(fullname == self.name, "FOUNDATION_SOURCE_MISMATCH")
        return self.path

    def get_data(self, path):
        require(path == self.path, "FOUNDATION_SOURCE_MISMATCH")
        return self.raw

    def get_code(self, fullname):
        return self.source_to_code(self.raw, self.get_filename(fullname))


def verify_source(expected):
    root = checked_root(Path(__file__).resolve().parents[1])
    pins = {**expected, "tools/hierarchy_mailbox.py": MAILBOX_SHA256}
    sources = {}
    try:
        for name, sha in pins.items():
            sources[name] = read_file(root, name)
            require(digest(sources[name]) == sha, "FOUNDATION_SOURCE_MISMATCH")
    except AcceptanceError as exc:
        raise AcceptanceError("FOUNDATION_SOURCE_MISMATCH") from exc
    names = ("hierarchy_mailbox", "hierarchy_lifecycle")
    # A matching filename cannot establish which bytes a caller previously loaded.
    # Never clear/reload caller modules or hide an earlier foreign search root.
    for name in names:
        path = root / "tools" / (name + ".py")
        cached, witnessed = sys.modules.get(name), _REPLAY_MODULES.get(name)
        if name in sys.modules or witnessed is not None:
            require(cached is not None and cached is witnessed, "FOUNDATION_SOURCE_MISMATCH")
            require(getattr(cached, "__file__", None) == str(path)
                    and getattr(getattr(cached, "__spec__", None), "origin", None) == str(path),
                    "FOUNDATION_SOURCE_MISMATCH")
        else:
            try:
                spec = importlib.util.find_spec(name)
            except (ImportError, ValueError, AttributeError) as exc:
                raise AcceptanceError("FOUNDATION_SOURCE_MISMATCH") from exc
            require(spec is None or spec.origin == str(path), "FOUNDATION_SOURCE_MISMATCH")
    for name in names:
        if name in _REPLAY_MODULES:
            continue
        path = root / "tools" / (name + ".py")
        loader = _VerifiedSourceLoader(name, path, sources["tools/" + name + ".py"])
        spec = importlib.util.spec_from_file_location(name, path, loader=loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            # Execute the exact bytes just hashed, never an unwitnessed .pyc.
            spec.loader.exec_module(module)
        except BaseException:
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
        _REPLAY_MODULES[name] = module
    lifecycle = _REPLAY_MODULES["hierarchy_lifecycle"]
    return lifecycle.Lifecycle, lifecycle.checkpoint


def held_cases(raw, legacy_ids):
    value = read_json(raw)
    exact(value, {"schema", "provenance", "cases"})
    require(value["schema"] == "aegis.foundation-case-matrix/v1"
            and type(value["cases"]) is list and 0 < len(value["cases"]) <= 32)
    held, seen, legacy = [], set(), set()
    for case in value["cases"]:
        exact(case, {"case_id", "kind", "requires", "observable"})
        require(type(case["case_id"]) is str and ID.fullmatch(case["case_id"]))
        require(case["case_id"] not in seen)
        seen.add(case["case_id"])
        require(case["kind"] in ("legacy", "coupled") and type(case["requires"]) is list)
        require(type(case["observable"]) is str and 0 < len(case["observable"]) <= 1024)
        if case["kind"] == "legacy":
            require(case["requires"] == [])
            legacy.add(case["case_id"])
        else:
            require(0 < len(case["requires"]) <= 16 and all(
                type(item) is str and 0 < len(item) <= 256 for item in case["requires"]))
            held.append({"case_id": case["case_id"], "requires": case["requires"]})
    require(legacy == legacy_ids)
    return held


def inspect_legacy(fixtures_root):
    root = checked_root(fixtures_root)
    raw_manifest = read_file(root, "manifest.json", 65536)
    definition = manifest(raw_manifest)
    payloads, total = {}, len(raw_manifest)
    for name, sha in definition["files"].items():
        limit = 65536 if name == definition["matrix"] else MAX_FILE
        raw = read_file(root, name, limit)
        total += len(raw)
        require(total <= MAX_TOTAL, "FOUNDATION_CORPUS_TOO_LARGE")
        require(digest(raw) == sha, "FOUNDATION_FIXTURE_HASH_MISMATCH")
        payloads[name] = raw
    require(corpus_names(root) == {"manifest.json", *payloads})
    held = held_cases(payloads[definition["matrix"]], {c["case_id"] for c in definition["legacy_cases"]})
    Lifecycle, checkpoint = verify_source(definition["source_files"])
    require(os.name == "posix", "FOUNDATION_UNSUPPORTED_HOST")
    results = []
    for case in definition["legacy_cases"]:
        prefix = case["prefix"] + "/"
        with tempfile.TemporaryDirectory(prefix="aegis-legacy-replay-") as temporary:
            store = Path(temporary)
            (store / "events").mkdir()
            (store / "policy.json").write_bytes(payloads[prefix + "policy.json"])
            for sequence in range(1, case["expected_sequence"] + 1):
                name = "events/%06d.json" % sequence
                (store / name).write_bytes(payloads[prefix + name])
            before = {name: read_file(store, name) for name in corpus_names(store)}
            try:
                lifecycle = Lifecycle(store)
                policy, state = lifecycle.load()
                observed = checkpoint(policy, state)
                status = lifecycle.status()
            except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
                raise AcceptanceError("FOUNDATION_LEGACY_MISMATCH") from exc
            expected = read_json(payloads[prefix + "checkpoint.json"])
            receipt = read_json(payloads[prefix + "receipt.json"])
            request = read_json(payloads[prefix + "request.json"])
            row = state["requests"].get(case["request_id"])
            require(observed == expected and row is not None, "FOUNDATION_LEGACY_MISMATCH")
            require(row["raw"] == request and "association" not in row
                    and "observations" not in row and "cancellation" not in row,
                    "FOUNDATION_LEGACY_MISMATCH")
            require((row["intent"]["id"] if row["intent"] else None) == case["expected_intent"]
                    and state["current"]["operator"] == case["expected_operator"]
                    and state["receipts"].get(case["receipt_id"]) == receipt
                    and status["head"] == state["head"] and status["execution_enabled"] is False,
                    "FOUNDATION_LEGACY_MISMATCH")
            require({name: read_file(store, name) for name in corpus_names(store)} == before,
                    "FOUNDATION_LEGACY_MISMATCH")
            results.append({"case_id": case["case_id"], "state": "verified",
                            "request_sha256": request["sha256"], "journal_head": state["head"],
                            "receipt_sha256": digest(payloads[prefix + "receipt.json"]),
                            "checkpoint_sha256": observed["sha256"], "bytes_unchanged": True})
    require(read_file(root, "manifest.json", 65536) == raw_manifest
            and all(read_file(root, name) == raw for name, raw in payloads.items()),
            "FOUNDATION_FIXTURE_HASH_MISMATCH")
    return {"schema": "aegis.foundation-acceptance/v1", "qualification": "reconstructed_fixture_only",
            "corpus_sha256": digest(raw_manifest), "source_manifest_sha256": digest(encoded(definition["source_files"])),
            "legacy_cases": results, "dependency_held": held, "native_authority": "not_established",
            "workflow_restart": "held"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("command", choices=("legacy",))
    args = parser.parse_args(argv)
    try:
        result = inspect_legacy(args.fixtures)
    except AcceptanceError as exc:
        print(encoded({"schema": "aegis.foundation-acceptance-error/v1", "code": exc.code}).decode())
        return 2
    print(encoded(result).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
