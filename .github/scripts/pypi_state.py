"""Compare what PyPI holds for a version with the verified files, so a re-run never
changes or masks PyPI content.

    python3 pypi_state.py plan --project P --version V --sums dist/SHA256SUMS --files publish-files.txt
    python3 pypi_state.py wait --project P --version V --sums dist/SHA256SUMS

`plan` prints state=absent|partial|identical (also into $GITHUB_OUTPUT), rewrites the
file list to the files PyPI lacks and exits 0; 1 when PyPI holds a file with another
digest or one not in SHA256SUMS; 2 when PyPI cannot be read (the list is untouched).
`wait` polls until PyPI holds exactly the verified files: 0 then, 1 on mismatch or timeout.
"""
import argparse
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

POLL_SECONDS = 10
WAIT_SECONDS = 300


class Unreadable(Exception):
    pass


def fetch_url(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except http.client.HTTPException as exc:  # a truncated answer is unreadable, not a crash
        raise OSError(f"{type(exc).__name__}: {exc}")


def read_sums(path):
    with open(path, encoding="utf-8") as f:
        pairs = (line.rstrip("\r\n").split("  ", 1) for line in f if line.strip())
        return {name: digest for digest, name in pairs}


def state(fetch, project, version, expected):
    """Return (state, detail): the files PyPI lacks, or the mismatch messages."""
    q = urllib.parse.quote
    url = f"https://pypi.org/pypi/{q(project, safe='')}/{q(version, safe='')}/json"
    try:
        status, body = fetch(url)
    except OSError as exc:
        raise Unreadable(f"{url}: {exc}")
    if status == 404:
        return "absent", sorted(expected)
    if status != 200:
        raise Unreadable(f"{url}: HTTP {status}")
    try:
        held = {u["filename"]: u["digests"]["sha256"] for u in json.loads(body)["urls"]}
    except (ValueError, KeyError, TypeError) as exc:
        raise Unreadable(f"{url}: unexpected answer ({exc!r})")
    bad = [f"{name}: PyPI sha256 {digest} != local sha256 {expected[name]}"
           for name, digest in sorted(held.items()) if name in expected and digest != expected[name]]
    bad += [f"{name}: on PyPI but not in SHA256SUMS" for name in sorted(set(held) - set(expected))]
    if bad:
        return "mismatch", bad
    missing = sorted(set(expected) - set(held))
    return ("absent" if not held else "partial" if missing else "identical"), missing


def plan(args, fetch):
    found, detail = state(fetch, args.project, args.version, read_sums(args.sums))
    if found == "mismatch":
        print("\n".join(detail), file=sys.stderr)
        return 1
    with open(args.files, encoding="utf-8") as f:
        paths = [line.strip() for line in f if line.strip()]
    with open(args.files, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(p + "\n" for p in paths if os.path.basename(p) in detail)
    print(f"state={found}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as f:
            f.write(f"state={found}\n")
    return 0


def wait(args, fetch, clock, sleep):
    expected = read_sums(args.sums)
    deadline = clock() + WAIT_SECONDS
    while True:
        try:
            found, detail = state(fetch, args.project, args.version, expected)
        except Unreadable as exc:  # the JSON API can lag an upload; retry until the deadline
            found, detail = "unreadable", [str(exc)]
        if found == "identical":
            return 0
        if found == "mismatch" or clock() >= deadline:
            why = "" if found == "mismatch" else f"not identical after {WAIT_SECONDS} s ({found}): "
            print(why + "; ".join(detail), file=sys.stderr)
            return 1
        sleep(POLL_SECONDS)


def main(argv=None, fetch=fetch_url, clock=time.monotonic, sleep=time.sleep):
    parser = argparse.ArgumentParser(prog="pypi_state.py")
    parser.add_argument("command", choices=("plan", "wait"))
    for flag in ("--project", "--version", "--sums"):
        parser.add_argument(flag, required=True)
    parser.add_argument("--files")
    args = parser.parse_args(argv)
    if args.command == "plan" and not args.files:
        parser.error("plan needs --files")
    try:
        return plan(args, fetch) if args.command == "plan" else wait(args, fetch, clock, sleep)
    except (Unreadable, OSError, ValueError) as exc:
        print(f"pypi_state: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
