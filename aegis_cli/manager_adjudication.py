"""Owner-side manager adjudication module command."""
from __future__ import annotations

import argparse
import json
import sys

from aegis_core.manager_adjudication import prepare, verify
from aegis_core.manager_policy import ManagerError
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import REDACTION_MASK_RE, clip_atomic_text, redact_command_secrets


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        print('{"status":"refused","reason":"invalid_arguments"}', file=sys.stderr)
        raise SystemExit(2)


def _parser():
    parser = _Parser(prog="aegis_cli.manager_adjudication", allow_abbrev=False)
    verbs = parser.add_subparsers(dest="verb", required=True)
    draft = verbs.add_parser("prepare", allow_abbrev=False)
    draft.add_argument("--manifest", required=True)
    check = verbs.add_parser("verify", allow_abbrev=False)
    check.add_argument("--anchor")
    for action in (draft, check):
        action.add_argument("--config", required=True)
        action.add_argument("--config-digest", required=True)
    return parser


def _episode_ids(value):
    if type(value) is dict:
        for key, item in value.items():
            if key == "episode_id" and type(item) is str:
                yield item
            else:
                yield from _episode_ids(item)
    elif type(value) is list:
        for item in value:
            yield from _episode_ids(item)


def _redact(value, episodes=()):
    canonical = sanitize_display(value, max_len=None)
    standalone = canonical in episodes
    if not standalone and any(episode in canonical for episode in episodes):
        return "[REDACTED]"

    redacted = redact_command_secrets(canonical)
    if standalone and REDACTION_MASK_RE.fullmatch(redacted) is None:
        return "[REDACTED]"
    return redacted


def _display(value, episodes, *, episode_id=False):
    if type(value) is dict:
        return {key: _display(item, episodes, episode_id=(key == "episode_id"))
                for key, item in value.items()}
    if type(value) is list:
        return [_display(item, episodes) for item in value]
    if type(value) is str:
        if episode_id and value in episodes:
            redacted = episodes[value]
        else:
            redacted = _redact(value, episodes)
        return clip_atomic_text(redacted, 128, policy="guidance")
    return value


def _render(report):
    # Verification bounds distinct assignments by the anchor limit and each ID by its grammar.
    ids = dict.fromkeys(_episode_ids(report))
    private = tuple(episode for episode in ids if _redact(episode) != episode)
    episodes = {}
    for episode in ids:
        if any(secret in episode for secret in private):
            # Brackets keep display ordinals outside the episode ID grammar.
            episodes[episode] = f"[redacted-episode-{len(episodes) + 1}]"
    return _display(report, episodes)


def main(argv=None):
    """Prepare a signing statement or print a rebuilt projection as JSON."""
    args = _parser().parse_args(argv)
    try:
        if args.verb == "prepare":
            result = prepare(args.config, args.config_digest, args.manifest)
        else:
            result = verify(args.config, args.config_digest, args.anchor)
    except ManagerError as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(_render(result), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
