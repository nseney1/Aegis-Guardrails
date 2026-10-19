"""Refuse a publish run unless it is the tag `v` + package version, at that tag's commit.

    python3 .github/scripts/release_guard.py   # reads GITHUB_REF_TYPE, GITHUB_REF_NAME, GITHUB_SHA

Exit 0 when every check passes, 1 with one line per failed check, 2 when it cannot
decide (no _version.py, no git, the tag missing from the checkout).
"""
import os
import re
import shutil
import subprocess
import sys

VERSION_FILE = os.path.join("aegis_core", "_version.py")
# The assignment setuptools reads without importing the package (pyproject.toml).
VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)


def check(ref_type, ref_name, sha, version, tag_commit):
    failed = []
    if ref_type != "tag":
        failed.append(f"ref type is '{ref_type}', not 'tag'")
    if ref_name != "v" + version:
        failed.append(f"tag '{ref_name}' is not 'v{version}'")
    if tag_commit is not None and tag_commit != sha:
        failed.append(f"tag commit {tag_commit} is not the run's commit {sha}")
    return failed


def _undecided(msg):
    print(f"release_guard: cannot decide: {msg}", file=sys.stderr)
    return 2


def main():
    ref_type = os.environ.get("GITHUB_REF_TYPE", "")
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    sha = os.environ.get("GITHUB_SHA", "")
    try:
        with open(VERSION_FILE, encoding="utf-8") as f:
            found = VERSION_RE.search(f.read())
    except OSError as exc:
        return _undecided(f"{VERSION_FILE}: {exc}")
    if not found:
        return _undecided(f"no __version__ assignment in {VERSION_FILE}")
    tag_commit = None
    if ref_type == "tag":
        git = shutil.which("git")
        if not git:
            return _undecided("git is not on PATH")
        ref = f"refs/tags/{ref_name}^{{commit}}"  # ^{commit} peels an annotated tag
        out = subprocess.run([git, "rev-parse", "--verify", "--quiet", ref],
                             capture_output=True, text=True)
        if out.returncode != 0:
            return _undecided(f"{ref} does not resolve in this checkout")
        tag_commit = out.stdout.strip()
    failed = check(ref_type, ref_name, sha, found.group(1), tag_commit)
    for msg in failed:
        print(f"release_guard: {msg}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
