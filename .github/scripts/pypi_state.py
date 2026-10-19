"""Compare what PyPI holds for a version with dist/SHA256SUMS, so a re-run never changes or masks it.

`plan --project P --version V --sums S --files F` prints state=absent|partial|identical (also to
$GITHUB_OUTPUT), rewrites F to the files PyPI lacks, exits 0; 1 if PyPI holds another digest or an
unlisted file; 2 if PyPI cannot be read (F untouched). `wait` (no --files) polls until PyPI holds
exactly the verified files: 0 then, 1 on a mismatch or after 300 s.
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

POLL_SECONDS, WAIT_SECONDS = 10, 300


def fetch_url(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except http.client.HTTPException as exc:  # a truncated answer is unreadable, not a crash
        raise OSError(f"{type(exc).__name__}: {exc}")


def state(fetch, project, version, expected):
    """(state, detail): detail is the files PyPI lacks, or the mismatch messages."""
    url = "https://pypi.org/pypi/{}/{}/json".format(*(urllib.parse.quote(v, safe="") for v in (project, version)))
    try:
        status, body = fetch(url)
    except OSError as exc:
        raise ValueError(f"{url}: {exc}")
    if status == 404:
        return "absent", sorted(expected)
    try:
        if status != 200:
            raise ValueError(f"HTTP {status}")
        held = {u["filename"]: u["digests"]["sha256"] for u in json.loads(body)["urls"]}
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"{url}: unexpected answer ({exc!r})")
    bad = [f"{n}: PyPI sha256 {d} != local sha256 {expected[n]}" for n, d in sorted(held.items())
           if n in expected and d != expected[n]]
    bad += [f"{n}: on PyPI but not in SHA256SUMS" for n in sorted(set(held) - set(expected))]
    missing = sorted(set(expected) - set(held))
    return ("mismatch", bad) if bad else ("absent" if not held else "partial" if missing else "identical", missing)


def plan(args, fetch, expected):
    found, detail = state(fetch, args.project, args.version, expected)
    if found == "mismatch":
        print("\n".join(detail), file=sys.stderr)
        return 1
    with open(args.files, encoding="utf-8") as f:
        paths = [line.strip() for line in f if line.strip()]
    with open(args.files, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(p + "\n" for p in paths if os.path.basename(p) in detail)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as f:
            f.write(f"state={found}\n")
    print(f"state={found}")
    return 0


def wait(args, fetch, expected, clock, sleep):
    deadline = clock() + WAIT_SECONDS
    while True:
        try:
            found, detail = state(fetch, args.project, args.version, expected)
        except ValueError as exc:  # unreadable; the JSON API can lag an upload: retry until the deadline
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
        with open(args.sums, encoding="utf-8") as f:
            expected = {n: d for d, n in (line.rstrip("\r\n").split("  ", 1) for line in f if line.strip())}
        return plan(args, fetch, expected) if args.command == "plan" else wait(args, fetch, expected, clock, sleep)
    except (OSError, ValueError) as exc:
        print(f"pypi_state: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
