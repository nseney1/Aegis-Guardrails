#!/usr/bin/env python3
"""Prepare an exact, read-only copy of a candidate and its baseline for an independent reviewer.

Reviewers had no file access, so source was mailed to them in chunks: about 109 messages and most of
the 1.06 MB between one orchestrator and its reviewer. Root runs this instead, then points the reviewer
at the folder. A reviewer who reads files needs no source relayed and sees the baseline beside the
change.

The copy is plain committed bytes taken with `git cat-file`, so no filter, attribute or repository
setting can change it. A symlink becomes a file holding its target and a submodule is only listed, so
reading the copy cannot lead outside it. `verify` compares the folder with its manifest, and a review
should cite the manifest hash that `prepare` printed.

Read-only modes prevent accidents, not a same-user process that changes them back, so `verify` is what
shows the copy is still what was reviewed. An empty `.git` at the top is there only because Codex needs
its working directory inside a Git checkout; it holds no commits and no hooks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (GIT_ID, encoded, matching, publish_file, require, safe_path, strict_json,  # noqa: E402
                               timestamp)


SCHEMA = "aegis.hierarchy-review/v1"
GIT = ["git", "-c", "core.fsmonitor=false", "--no-optional-locks"]
SIDES = ("base", "candidate")
GIT_TIMEOUT_SECONDS = 300
CHUNK_BYTES = 1048576
MAX_PROBLEMS = 100
MEANING = ("Exact committed bytes. A symlink is a plain file holding its target, and a submodule is listed but not followed. "
           "Run verify before relying on this folder; read-only modes alone prove nothing.")


def git(repository, *arguments, **options):
    return subprocess.run([*GIT, *arguments], cwd=repository, capture_output=True, timeout=GIT_TIMEOUT_SECONDS, **options)


def exact_commit(repository, commit, label, expected_tree):
    matching(commit, GIT_ID, label)
    found = git(repository, "rev-parse", "--verify", "-q", commit + "^{commit}")
    require(found.returncode == 0 and found.stdout.decode().strip() == commit, label + " commit is not in the repository: " + commit)
    tree = git(repository, "rev-parse", commit + "^{tree}").stdout.decode().strip()
    require(expected_tree is None or tree == expected_tree, label + " tree is %s, not the expected %s" % (tree, expected_tree))
    return {"commit": commit, "tree": tree}


def tree_entries(repository, commit):
    listed = git(repository, "ls-tree", "-r", "-z", "--full-tree", commit)
    require(listed.returncode == 0, "could not list the tree of " + commit)
    entries = []
    for row in listed.stdout.split(b"\0"):
        if not row:
            continue
        head, _, name = row.partition(b"\t")
        mode, kind, oid = head.decode("ascii").split()
        path = os.fsdecode(name)
        # Git refuses to check these out, but a crafted tree object can still hold them.
        require(not path.startswith("/") and all(part not in ("", ".", "..") and part.lower() != ".git" for part in path.split("/")),
                "unsafe path in the tree of %s: %r" % (commit, path))
        entries.append((mode, kind, oid, path))
    return entries


def export(repository, entries, folder):
    """Writes raw blobs, because even `git archive` applies attributes such as export-ignore."""
    rows = []
    folder.mkdir()
    with subprocess.Popen([*GIT, "cat-file", "--batch"], cwd=repository, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
        for mode, kind, oid, path in entries:
            if kind == "commit":
                rows.append({"path": path, "mode": mode, "commit": oid})
                continue
            require(kind == "blob", "unsupported tree entry: " + kind)
            process.stdin.write(oid.encode() + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            require(len(header) == 3 and header[1] == b"blob", "could not read object " + oid)
            remaining = int(header[2])
            target = folder / path
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with open(target, "xb") as stream:
                while remaining:
                    chunk = process.stdout.read(min(CHUNK_BYTES, remaining))
                    require(bool(chunk), "object ended early: " + oid)
                    stream.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            process.stdout.read(1)
            rows.append({"path": path, "mode": mode, "sha256": digest.hexdigest()})
        process.stdin.close()
    return rows


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_output(repository, path, *arguments):
    with open(path, "xb") as stream:
        done = subprocess.run([*GIT, *arguments], cwd=repository, stdout=stream, stderr=subprocess.PIPE, timeout=GIT_TIMEOUT_SECONDS)
    require(done.returncode == 0, "git failed writing " + path.name + ": " + done.stderr.decode(errors="replace")[:512])
    return file_digest(path)


def lock_down(folder):
    for current, folders, files in os.walk(folder, topdown=False):
        for name in files:
            os.chmod(os.path.join(current, name), 0o444)
        for name in folders:
            os.chmod(os.path.join(current, name), 0o555)


def unlock(folder):
    os.chmod(folder, 0o755)
    for current, folders, files in os.walk(folder):
        for name in folders:
            os.chmod(os.path.join(current, name), 0o755)
        for name in files:
            path = os.path.join(current, name)
            if not os.path.islink(path):
                os.chmod(path, 0o644)


def prepare(args):
    repository = safe_path(args.repository)
    out = safe_path(args.out)
    top = git(repository, "rev-parse", "--show-toplevel")
    require(git(repository, "rev-parse", "--git-dir").returncode == 0, "not a Git repository: " + str(repository))
    if top.returncode == 0 and top.stdout.strip():
        try:
            out.relative_to(Path(top.stdout.decode().strip()))
        except ValueError:
            pass
        else:
            raise ValueError("the copy must be outside the repository, or it would make the source look changed")
    require(not out.exists(), "folder already exists: " + str(out))
    sides = {"base": exact_commit(repository, args.base, "base", args.expect_base_tree),
             "candidate": exact_commit(repository, args.candidate, "candidate", args.expect_candidate_tree)}
    entries = {side: tree_entries(repository, sides[side]["commit"]) for side in SIDES}
    out.parent.mkdir(parents=True, exist_ok=True)
    pending = out.parent / (".pending-" + uuid.uuid4().hex)
    pending.mkdir(mode=0o700)
    try:
        for side in SIDES:
            rows = export(repository, entries[side], pending / side)
            listing = pending / (side + ".files.jsonl")
            listing.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="ascii")
            sides[side].update(files=len(rows), listing_sha256=file_digest(listing))
        base, candidate = sides["base"]["commit"], sides["candidate"]["commit"]
        diff = write_output(repository, pending / "changes.diff", "diff", "--no-ext-diff", "--no-textconv", "--no-color",
                            "--full-index", "--find-renames", base, candidate)
        commits = write_output(repository, pending / "commits.txt", "log", "--no-color", "--no-show-signature",
                               "--format=commit %H%nAuthor: %an <%ae>%nDate: %aI%n%n%B", base + ".." + candidate)
        changed = git(repository, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, candidate)
        require(changed.returncode == 0, "could not list the changed files")
        count = sum(1 for name in changed.stdout.split(b"\0") if name)
        manifest = {"schema": SCHEMA, "created_at": timestamp(), "repository": str(repository), "base": sides["base"],
                    "candidate": sides["candidate"], "diff_sha256": diff, "commits_sha256": commits, "changed_files": count,
                    "meaning": MEANING}
        raw = encoded(manifest) + b"\n"
        publish_file(pending / "manifest.json", raw)
        made = subprocess.run(["git", "init", "-q", "--template=", str(pending)], capture_output=True, timeout=60,
                              env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        require(made.returncode == 0, "could not create the empty Git folder")
        lock_down(pending)
        pending.rename(out)
        os.chmod(out, 0o555)
    except BaseException:
        if pending.exists():
            unlock(pending)
            shutil.rmtree(pending)
        raise
    return 0, {"out": str(out), "manifest_sha256": hashlib.sha256(raw).hexdigest(), "base": sides["base"],
               "candidate": sides["candidate"], "diff_sha256": diff, "changed_files": count}


def load_manifest(out):
    path = out / "manifest.json"
    require(path.is_file(), "no review manifest here: " + str(out))
    raw = path.read_bytes()
    manifest = strict_json(raw.decode("utf-8"))
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA, "no review manifest here: " + str(out))
    return manifest, raw


def side_problems(out, side, listing_expected):
    listing = out / (side + ".files.jsonl")
    problems = []
    rows = []
    if not listing.is_file():
        problems.append(listing.name + " is missing")
    else:
        if file_digest(listing) != listing_expected:
            problems.append(listing.name + " changed")
        rows = [json.loads(line) for line in listing.read_text(encoding="ascii").splitlines()]
    expected = {row["path"]: row["sha256"] for row in rows if "sha256" in row}
    folder = out / side
    seen = set()
    for current, folders, files in os.walk(folder):
        for name in folders + files:
            path = Path(current) / name
            if path.is_symlink():
                problems.append("%s/%s became a symlink" % (side, path.relative_to(folder)))
            elif stat.S_IMODE(path.lstat().st_mode) & 0o222:
                problems.append("%s/%s is writable" % (side, path.relative_to(folder)))
        for name in files:
            path = Path(current) / name
            relative = str(path.relative_to(folder))
            seen.add(relative)
            if relative not in expected:
                problems.append("%s/%s was added" % (side, relative))
            elif not path.is_symlink() and file_digest(path) != expected[relative]:
                problems.append("%s/%s changed" % (side, relative))
    problems += ["%s/%s is missing" % (side, relative) for relative in sorted(set(expected) - seen)]
    return problems


def verify(args):
    out = safe_path(args.out)
    manifest, raw = load_manifest(out)
    recorded = hashlib.sha256(raw).hexdigest()
    problems = []
    if args.expect_manifest is not None and recorded != args.expect_manifest:
        problems.append("manifest.json does not match the recorded hash")
    for name, field in (("changes.diff", "diff_sha256"), ("commits.txt", "commits_sha256")):
        path = out / name
        if not path.is_file():
            problems.append(name + " is missing")
        elif file_digest(path) != manifest[field]:
            problems.append(name + " changed")
    for side in SIDES:
        problems += side_problems(out, side, manifest[side]["listing_sha256"])
    known = {"manifest.json", "changes.diff", "commits.txt", ".git", *SIDES, *(side + ".files.jsonl" for side in SIDES)}
    problems += [entry.name + " was added" for entry in sorted(out.iterdir()) if entry.name not in known]
    return (3 if problems else 0), {"ok": not problems, "manifest_sha256": recorded, "base": manifest["base"]["commit"],
                                    "candidate": manifest["candidate"]["commit"], "problems": problems[:MAX_PROBLEMS],
                                    "problem_count": len(problems)}


def remove(args):
    out = safe_path(args.out)
    load_manifest(out)
    unlock(out)
    shutil.rmtree(out)
    return 0, {"removed": str(out)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    made = commands.add_parser("prepare", help="Make the read-only copy")
    made.add_argument("--repository", required=True, help="Absolute path to a local repository holding both commits")
    made.add_argument("--base", required=True, help="Full commit ID of the baseline")
    made.add_argument("--candidate", required=True, help="Full commit ID under review")
    made.add_argument("--out", required=True, help="Absolute path for the new folder, outside the repository")
    made.add_argument("--expect-base-tree", default=None)
    made.add_argument("--expect-candidate-tree", default=None)
    checked = commands.add_parser("verify", help="Compare a copy with its manifest")
    checked.add_argument("--out", required=True)
    checked.add_argument("--expect-manifest", default=None, help="The manifest hash prepare printed")
    commands.add_parser("remove", help="Delete a copy this tool made").add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        code, result = {"prepare": prepare, "verify": verify, "remove": remove}[args.command](args)
    except (ValueError, OSError, UnicodeError, RecursionError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
