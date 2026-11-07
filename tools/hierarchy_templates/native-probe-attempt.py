"""Append one nonce line to one path, for the Aegis native probe, and report the outcome as JSON.

The probe seeds this file, pins its sha256 and asks a Codex role to run it once per target. The verdict
never comes from this output: the probe reads the target file and the host's own command record.
"""
import json
import os
import sys


def main(argv):
    if len(argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: native-probe-attempt.py PATH NONCE"}))
        return 2
    path, nonce = argv
    try:
        # O_APPEND, not O_EXCL: the CODEX_HOME target is config.toml, which may already exist.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write("aegis-native-probe %s\n" % nonce)
    except OSError as exc:
        print(json.dumps({"ok": False, "path": path, "nonce": nonce, "errno": exc.errno,
                          "error": "OSError: " + str(exc)}))
        return 1
    print(json.dumps({"ok": True, "path": path, "nonce": nonce}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
