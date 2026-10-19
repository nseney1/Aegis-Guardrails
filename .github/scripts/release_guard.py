"""Refuse a publish run unless its ref is the tag `v` + package version at that tag's commit.

Reads GITHUB_REF_TYPE, GITHUB_REF_NAME and GITHUB_SHA. Exit 0 when every check passes, 1 with
one line per failed check, 2 when it cannot decide (no _version.py, no git, tag not checked out).
"""
import os
import re
import shutil
import subprocess
import sys

VERSION_FILE = os.path.join("aegis_core", "_version.py")


def check(ref_type, ref_name, sha, version, tag_commit):
    failed = [f"ref type is '{ref_type}', not 'tag'"] if ref_type != "tag" else []
    if ref_name != "v" + version:
        failed.append(f"tag '{ref_name}' is not 'v{version}'")
    if tag_commit is not None and tag_commit != sha:
        failed.append(f"tag commit {tag_commit} is not the run's commit {sha}")
    return failed


def main():
    env = os.environ.get
    ref_type, ref_name, sha = env("GITHUB_REF_TYPE", ""), env("GITHUB_REF_NAME", ""), env("GITHUB_SHA", "")
    try:
        with open(VERSION_FILE, encoding="utf-8") as f:  # the assignment setuptools reads unimported
            version = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', f.read(), re.M).group(1)
    except (OSError, AttributeError) as exc:
        return _undecided(f"no __version__ in {VERSION_FILE}: {exc}")
    tag_commit = None
    if ref_type == "tag":
        git, ref = shutil.which("git"), f"refs/tags/{ref_name}^{{commit}}"  # ^{commit} peels annotated tags
        out = git and subprocess.run([git, "rev-parse", "--verify", "--quiet", ref], capture_output=True, text=True)
        if not out or out.returncode != 0:
            return _undecided(f"{ref} does not resolve" if git else "git is not on PATH")
        tag_commit = out.stdout.strip()
    failed = check(ref_type, ref_name, sha, version, tag_commit)
    for msg in failed:
        print(f"release_guard: {msg}", file=sys.stderr)
    return 1 if failed else 0


def _undecided(msg):
    print(f"release_guard: cannot decide: {msg}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
