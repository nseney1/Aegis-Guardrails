#!/usr/bin/env python3
"""Verify a provision's checkout before loading its runtime. Stdlib only, also copied into each base.

This is reproducibility, not protected authentication: a principal able to rewrite the base can rewrite
its pin. Existing bases are never refreshed. Recover source drift by handing off into a new base.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile

BOOTSTRAP = "runtime-source.py"
MODULE = "tools/hierarchy_runtime_source.py"
IMPORTABLE = (".py", ".pyc", ".pyo", ".so", ".pyd", ".dll", ".pth", ".zip")
ENTRIES = {"hierarchy_mailbox.py", "hierarchy_mailbox_mcp.py", "hierarchy_launcher.py", "hierarchy_provision.py",
           "hierarchy_wake.py"}
RECOVERY = "reprovision into a new base through the existing handoff flow"


def git(source, *arguments, data=None):
    # Kept self-contained: importing the source's Git helper here would execute it before verification.
    # Match hierarchy_git's object-read policy, including the empty transport allowlist on older Git.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
               GIT_PROTOCOL_FROM_USER="0", GIT_ALLOW_PROTOCOL="")
    ran = subprocess.run(["git", "--no-optional-locks", "--no-replace-objects", "-c", "core.fsmonitor=false",
                          "-c", "protocol.allow=never", *arguments], cwd=source, env=env,
                         input=data, capture_output=True, timeout=60)
    if ran.returncode:
        raise ValueError("Git object read failed: " + ran.stderr.decode("utf-8", "replace").strip())
    return ran.stdout


def identity(source):
    rows = git(source, "rev-parse", "--show-toplevel", "HEAD", "HEAD^{tree}").decode().splitlines()
    if len(rows) != 3 or Path(rows[0]).resolve() != Path(source).resolve():
        raise ValueError("source checkout must be the repository root")
    return rows[1], rows[2]


def failure(setup, observed, reason):
    setup = setup if isinstance(setup, dict) else {}
    return ValueError("runtime source verification failed: expected commit=%s tree=%s; observed commit=%s tree=%s; %s; %s" %
                      (setup.get("source_commit"), setup.get("source_tree"), observed[0], observed[1], reason, RECOVERY))


def runtime_path(name, mode):
    return (name.startswith("tools/") or name.startswith("aegis_") or mode == b"100755" or
            name.lower().endswith(IMPORTABLE))


def blobs(source, entries):
    if not entries:
        return []
    raw = git(source, "cat-file", "--batch", data=b"".join(oid + b"\n" for _, oid in entries))
    cursor, result = 0, []
    for name, oid in entries:
        end = raw.index(b"\n", cursor)
        header = raw[cursor:end].split()
        if len(header) != 3 or header[0] != oid or header[1] != b"blob":
            raise ValueError("missing runtime object: " + name)
        size = int(header[2])
        cursor = end + 1
        body = raw[cursor:cursor + size]
        if len(body) != size or raw[cursor + size:cursor + size + 1] != b"\n":
            raise ValueError("incomplete runtime object: " + name)
        result.append((name, body))
        cursor += size + 1
    if cursor != len(raw):
        raise ValueError("unexpected Git object output")
    return result


def verify(setup, base=None):
    """Compare actual bytes with committed blobs; status alone cannot see hidden-index or ignored code."""
    observed = ("unavailable", "unavailable")
    try:
        source = Path(setup["source"])
        for key in ("source_commit", "source_tree"):
            if not isinstance(setup.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", setup[key]):
                raise ValueError("invalid recorded " + key)
        observed = identity(source)
        if observed != (setup["source_commit"], setup["source_tree"]):
            raise ValueError("checkout identity changed")
        for row in git(source, "ls-files", "-v", "-z").split(b"\0"):
            if row and (row[:1].islower() or row[:1] == b"S"):
                raise ValueError("hidden index state: " + os.fsdecode(row[2:]))
        if git(source, "diff-index", "--cached", "--name-only", setup["source_commit"], "--").strip():
            raise ValueError("index differs from recorded commit")
        # Omitting --exclude-standard is deliberate: ignored code can still be imported.
        for row in git(source, "ls-files", "--others", "-z").split(b"\0"):
            if row:
                name = os.fsdecode(row)
                path = source / name
                if name.lower().endswith(IMPORTABLE) or path.is_symlink() or path.is_dir():
                    raise ValueError("untracked or ignored importable code: " + name)
        entries = []
        for row in git(source, "ls-tree", "-r", "-z", setup["source_commit"]).split(b"\0"):
            if not row:
                continue
            metadata, raw_name = row.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            name = os.fsdecode(raw_name)
            if runtime_path(name, mode):
                if kind != b"blob" or mode not in (b"100644", b"100755"):
                    raise ValueError("runtime path must be a regular file: " + name)
                entries.append((name, oid))
        contents = blobs(source, entries)
        bootstrap = None
        for name, committed in contents:
            path = source / name
            if any(parent.is_symlink() for parent in (path, *path.parents) if parent != source.parent):
                raise ValueError("runtime path contains a symbolic link: " + name)
            if not path.is_file() or path.read_bytes() != committed:
                raise ValueError("runtime bytes differ: " + name)
            if name == MODULE:
                bootstrap = committed
        if bootstrap is None:
            raise ValueError("recorded source has no runtime source verifier")
        if base is not None:
            kept = Path(base) / BOOTSTRAP
            if not kept.is_file():
                raise ValueError("runtime source verifier is missing")
            if kept.is_symlink() or kept.read_bytes() != bootstrap:
                raise ValueError("retained runtime source verifier differs")
        return bootstrap
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        raise failure(setup, observed, str(exc)) from exc


def entry_args(setup, entry):
    base = Path(setup["mailbox_root"]).parent
    return ["-I", "-B", str(base / BOOTSTRAP), "--provision", str(base / "provision.json"),
            "--entry", str(Path(setup["source"]) / "tools" / entry), "--"]


def run(provision, entry, arguments):
    setup = json.loads(Path(provision).read_text(encoding="utf-8"))
    verify(setup, Path(provision).parent)
    path = Path(entry)
    if path.name not in ENTRIES or path != Path(setup["source"]) / "tools" / path.name:
        raise ValueError("runtime entry is outside the recorded source")
    # -B stops writes but still READS caches. Redirect cache lookup to a new empty directory before peer imports.
    with tempfile.TemporaryDirectory(prefix="aegis-runtime-cache-") as cache:
        sys.dont_write_bytecode = True
        sys.pycache_prefix = cache
        sys._aegis_verified_runtime_entry = str(path)
        sys.argv = [str(path), *arguments]
        runpy.run_path(str(path), run_name="__main__")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provision", required=True)
    parser.add_argument("--entry", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        run(args.provision, args.entry, args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
